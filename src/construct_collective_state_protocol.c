/*
 * Steward.
 *     
 * The contents of this file are subject to the Steward Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/steward/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Steward are:
 *  Yair Amir, Claudiu Danilov, Danny Dolev, Jonathan Kirsch, John Lane,
 *  Cristina Nita-Rotaru, Josh Olsen, and David Zage.
 *
 * Copyright (c) 2005 - 2010 
 * The Johns Hopkins University, Purdue University, The Hebrew University.
 * All rights reserved.
 *
 */

/*-------------------------------------------------
  File:  construct_collective_state_protocol.c
  Date:  October 15, 2005
  Usage: Implements protocol ccs
--------------------------------------------------*/

#include "construct_collective_state_protocol.h"
#include "construct_collective_state_util.h"
#include "utility.h"
#include "openssl_rsa.h"
#include "util/alarm.h"
#include "util/memory.h"
#include "stdutil/stdhash.h"
#include "prepare_certificate_receiver.h"
#include "threshold_sign.h"
#include "global_reconciliation.h"
#include <string.h>

retrans_struct CCS_RETRANS[NUM_CONTEXTS]; 

retrans_struct CCS_GLOBAL_RETRANS;

signed_message *CCS_UNION_SIG_SHARE[2][NUM_SERVER_SLOTS]; /* storage for sig
							    share messages */

signed_message *CCS_UNION_MESSAGE[2]; /* storage of actual union messages --
					these have valid threshold signatures
					     */
signed_message *GLOBAL_CCS_UNION[NUM_SITES+1];

util_stopwatch UNION_FORWARD_STOPWATCH[NUM_SITES+1];


/* Globally-accessible data structures */
extern global_data_struct  GLOBAL;
extern pending_data_struct PENDING;
extern server_variables    VAR;

/* Locally-accessible global variables */
ccs_state_struct             CCS_STATE;
ccs_collected_reports_struct CCS_REPORTS;
ccs_union_struct             CCS_UNION;

int32u CCS_global_target_aru_last_set_in_view;
int32u CCS_global_target_aru;
int32u CCS_last_globally_constrained_view;

/*---------------------------------------------------------------------------*/
void   CCS_Invocation_Handler    (signed_message *m);
void   Respond_To_CCS_Invocation (int32u aru, int32u context);

void   CCS_Report_Handler        (signed_message *m);
int32u Check_Report_Contents    (signed_message *m);
void   CCS_Description_Handler   (signed_message *m);

void   CCS_Send_Description_And_Reports(int32u context);

void   CCS_Begin_Collection_Phase(int32u context);
void   Union                    (int32u context);
int32u Mark_Union_Entries       (int32u context);

void  CCS_Allocate_Receiver_Slots      ( signed_message *m );
void  CCS_Allocate_Union_Receiver_Slots(int32u context);

void Send_Global_Union_Contents_To_Leader_Site(signed_message *ccs_union);

void CCS_Forward_Union_Message( signed_message *ccs_union ); 

/*---------------------------------------------------------------------------*/

/*
 * The protocol uses the following message pattern:
 *
 * 1. Representative to all:          CCS_Invocation_Message(aru)
 * 2. All updated to representative:  CCS_Report_Message
 * 3. Representative to all:          CCS_Description_Message
 */

void CCS_Dispatcher(signed_message *m)
{
  switch(m->type) {
  case CCS_INVOCATION_TYPE:
    CCS_Invocation_Handler(m);
    break;

  case CCS_REPORT_TYPE:
    CCS_Report_Handler(m);
    break;

  case CCS_DESCRIPTION_TYPE:
    CCS_Description_Handler(m);
    break;

  default:
    Alarm(DEBUG, "CCS: Unexpected message type!\n");
  }
}

void CCS_Send_Invocation_Message( int32u context, int32u aru ) {

  signed_message *invocation;

    if( UTIL_I_Am_In_Leader_Site() && VAR.My_Site_ID == 2 
	    && context == GLOBAL_CONTEXT ) { 
        Alarm(DEBUG, "CCS_Send_Invocation_Message.\n");
    }

    Alarm(DEBUG,"CCS_Send_Invocation_Message\n");

    /*if(context == GLOBAL_CONTEXT)
      return;
    */

   if(UTIL_Get_View(context) > CCS_STATE.Latest_Invocation_View[context]) {
     CCS_STATE.Latest_Invocation_View[context] = UTIL_Get_View(context);

     invocation = Construct_CCS_Invocation( context, aru ); 

     UTIL_RETRANS_Clear( &CCS_RETRANS[context] );

     /* Configure retransmission to multicast the invocation message. */
     CCS_RETRANS[context].dest_site_id = 0;
     CCS_RETRANS[context].dest_server_id = 0;

     UTIL_RETRANS_Add_Message( &CCS_RETRANS[context], invocation ); 
     UTIL_RETRANS_Start( &CCS_RETRANS[context] ); 
     
     dec_ref_cnt(invocation);

     Alarm(CCS_PRINT, "Sending Invocation Message view: %d context: %d\n",
	     UTIL_Get_View(context), context );
   }
}

void CCS_Invocation_Handler(signed_message *m)
{
  ccs_invocation_message *pim = (ccs_invocation_message *)(m+1);
  int32u context             = pim->context;
  int32u aru                 = pim->aru;
  
  /*
   * If my aru is at least as high as the representative's, I
   * construct a report message.  I then send the data I am reporting
   * to the representative.
   *   
   * Otherwise, if my aru is less than the representative's, I attempt
   * to bring my aru up to the representative's via reconciliation.  A
   * callback is used so that a response will be generated when the
   * server's aru becomes high enough.  See CCS_Response_Decider()
   */

  Alarm(CCS_PRINT, "***Received Invocation Message: %d\n", context);


  /* Store only the first invocation message I receive */
  if(CCS_STATE.State[context] == INITIAL_STATE) {
    CCS_STATE.Invocation_ARU[context] = aru;  
    CCS_STATE.State[context] = INVOCATION_RECEIVED;

    if(UTIL_I_Am_Representative()) {
      Respond_To_CCS_Invocation(UTIL_Get_ARU(context), context);
      CCS_STATE.State[context] = COLLECTING_REPORT_CONTENTS;
    }
    else
      CCS_Response_Decider(context);
  }
}

void CCS_Response_Decider( int32u context ) 
{
  int32u my_aru;

  /* 
   * This function is called when the aru is increased or when an invocation
   * message is received. 
   */
  
  if(CCS_STATE.State[context] != INVOCATION_RECEIVED)
    return;

  Alarm(DEBUG, "\n\n***CCS_Response_Decider went through!***\n\n");


  my_aru = UTIL_Get_ARU(context);
  
  if(my_aru >= CCS_STATE.Invocation_ARU[context])
    Respond_To_CCS_Invocation(my_aru, context);
}

void Respond_To_CCS_Invocation(int32u my_aru, int32u context)
{
  signed_message *ccs_rm;
  
  /*
   * Send my report message to the representative.  Then send the contents
   * of the report to the representative.
   *
   * Both will be retransmitted until the description message is
   * received.  
   *
   * If I am the representative, I construct a report, but do not send
   * or retransmit the report contents, since I am guaranteed to have
   * everything I need.
   */

  ccs_rm = Construct_CCS_Report(my_aru, context);

  if(UTIL_I_Am_Representative()) {
    inc_ref_cnt(ccs_rm);
    CCS_REPORTS.Report_List[context][VAR.My_Server_ID] = ccs_rm;
    CCS_REPORTS.num_reports_collected[context]++;
    CCS_REPORTS.num_completed_reports[context]++;
    CCS_REPORTS.completed_report_list[context][VAR.My_Server_ID] = TRUE;
  }
  else {
    UTIL_RETRANS_Clear(&CCS_RETRANS[context]);
    UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], ccs_rm); 
    
    /* Add all components of the report list to the retransmission list */
    Send_Report_Contents(UTIL_Representative(), ccs_rm);

    /* Send only to the representative */
    CCS_RETRANS[context].dest_server_id = UTIL_Representative();

    UTIL_RETRANS_Start( &CCS_RETRANS[context] ); 

    CCS_STATE.State[context] = REPORT_SENT;

    if( UTIL_I_Am_In_Leader_Site() && VAR.My_Site_ID == 2 
	&& context == GLOBAL_CONTEXT ) {     
      Alarm(DEBUG, "Responded to invocation message in context %d\n", context);
    }

    Alarm(CCS_PRINT, "Responding to invocation message in context %d\n", 
	  context);
  }
  
  dec_ref_cnt(ccs_rm);
}

void CCS_Report_Handler(signed_message *m)
{
  ccs_report_message *report;
  int32u id, c;
  byte report_digest[DIGEST_SIZE];

  report = (ccs_report_message *)(m+1);
  id = m->machine_id;
  c  = report->context;

  /*
   * Ways to bail out:
   *  1. I already have 2f+1 report messages in this context
   *  2. I already have a report from this server in this context.
   */

  if(CCS_REPORTS.num_completed_reports[c] >= (2*VAR.Faults+1)) {
    Alarm(DEBUG, "Already collected at least 2f+1 reports.\n");
    return;
  }
  
  if(CCS_REPORTS.Report_List[c][id] != NULL) {
    Alarm(DEBUG, "Already received report from %d.\n", id);
    return;
  }

  /* 
   * If I am the representative, add this report list to my
   * collection, and check to see if it's completed.  If I now have
   * 2f+1, send a description, send the reports, compute the union,
   * and send out everything in the union.
   *
   * If I can't complete it at this time, the callback function will be
   * CCS_Report_Decider()
   */
  if(UTIL_I_Am_Representative()) {
    CCS_Allocate_Receiver_Slots(m);

    inc_ref_cnt(m);
    CCS_REPORTS.Report_List[c][id] = m;
    CCS_REPORTS.num_reports_collected[c]++;
    
    Alarm(CCS_PRINT, "Storing report for server %d, context %d\n", id, c);

    CCS_Report_Decider(c);
  }
  
  /*
   * If I am not the representative, then store the CCS_Report only
   * if I've already received the CCS_Reports_Description message
   * from the representative and this is one of the needed reports,
   * and I haven't already finished collecting it, and the digest matches.
   *
   * If this is the last report from the description that I need, proceed
   * to the next phase of computing the union and collecting what is needed
   * from the union.
   */
  else {
    if((CCS_REPORTS.Description[c] != NULL) &&
       (CCS_REPORTS.report_in_description[c][id] == TRUE)  &&
       (CCS_REPORTS.completed_report_list[c][id] == FALSE)) {
	
      /*
       * 1. Compute the digest of this report
       * 2. Compare it to the digest I have stored from description 
       */
      OPENSSL_RSA_Make_Digest(m, m->len, report_digest);
      
      if(OPENSSL_RSA_Digests_Equal(
	  (byte *)CCS_REPORTS.report_digests[c][id].digest, report_digest)) {
	Alarm(DEBUG, "Storing report for server %d\n", id);

	CCS_Allocate_Receiver_Slots(m); 

	inc_ref_cnt(m);
	CCS_REPORTS.Report_List[c][id] = m;
	CCS_REPORTS.num_reports_collected[c]++;
	  
	if(CCS_REPORTS.num_reports_collected[c] == (2*VAR.Faults+1))
	  CCS_Begin_Collection_Phase(c);
      }
    }
  }
}

void CCS_Report_Decider(int32u context)
{
  int32u my_aru, i;
  signed_message *m;
  ccs_report_message *report;

  if(CCS_STATE.State[context] != COLLECTING_REPORT_CONTENTS)
    return;

  my_aru = UTIL_Get_ARU(context);      

  /* 
   * The goal of this loop is to increment num_completed_reports, if
   * possible, by examining those entries for which I have a report
   * but have not previously completed collecting all of its contents
   * (or if my aru was not high enough).  If I go through and reach
   * 2f+1 completed reports, I move on to the next stage, and change my
   * state so I don't repeat this process.
   */
  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    if(CCS_REPORTS.completed_report_list[context][i] == FALSE) {
      if(CCS_REPORTS.Report_List[context][i] != NULL) {
	m      = CCS_REPORTS.Report_List[context][i];
	report = (ccs_report_message *)(m + 1);

	if(my_aru >= report->aru) {
	  if(Check_Report_Contents(m)) {
	    CCS_REPORTS.num_completed_reports[context]++;
	    CCS_REPORTS.completed_report_list[context][i] = TRUE;
	  }
      
	  if(CCS_REPORTS.num_completed_reports[context] == (2*VAR.Faults + 1)) {
	    CCS_Send_Description_And_Reports(context);
	    break;
	  }
	}
      }
    }
  }
}


void CCS_Send_Description_And_Reports(int32u context)
{
  signed_message *description;
  signed_message *union_share;
  ccs_union_message *union_specific;

  description = Construct_CCS_Description(context);

  CCS_REPORTS.Description[context] = description;
  
  Alarm(DEBUG, "Finished constructing description message.\n");
	  
  /*
   * Stop sending the invocation message, start sending:
   *     1. Description
   *     2. Reports described in Description
   *     3. Union contents for reports described in Description
   */
  UTIL_RETRANS_Clear(&CCS_RETRANS[context]);
  
  UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], description);

  /* Add the reports to the retransmission list */
  Send_Described_Reports(description);
	  
  Union(context);
  
  /* Add the union contents to the retransmission list */
  Send_Union_Contents(context);

  /* Compute my threshold share */
  union_share = CCS_Construct_Threshold_Share(context);
  THRESH_Invoke_Threshold_Signature(union_share);

  union_specific = (ccs_union_message *)(union_share + 1);
  Alarm(DEBUG, "After Invoke, Context = %d\n", 
	union_specific->context);
  Alarm(DEBUG, "After Invoke, LocalView = %d\n", 
	union_specific->local_view);
  
  dec_ref_cnt(union_share);

  UTIL_RETRANS_Start(&CCS_RETRANS[context]);

  Alarm(CCS_PRINT, "Sending Description, Reports, Union contents\n");

  if( UTIL_I_Am_In_Leader_Site() && VAR.My_Site_ID == 2 
      && context == GLOBAL_CONTEXT ) { 
    Alarm(DEBUG, "Send Description, Reports, Union in context %d\n", context);
  }
  CCS_STATE.State[context] = COLLECTING_SIG_SHARES;
}

void CCS_Allocate_Receiver_Slots( signed_message *report ) 
{
  int32u c;
  int32u i;
  ccs_pending_report_entry *entry;
  
  ccs_report_message *report_specific; 
  
  report_specific = (ccs_report_message*)(report+1);
  
  c = report_specific->context;
  
  if ( c != PENDING_CONTEXT ) {
    return;
  }
  
  for (i = 1; i <= report_specific->num_entries; i++) {
    entry = (ccs_pending_report_entry*) Get_Report_Entry(report_specific, i);

    if(entry->type == INTERMEDIATE_TYPE) {
      PCRCV_Configure_Prepare_Certificate_Receiver(entry->local_view,
						   entry->global_view, 
						   entry->seq, entry->digest); 
    }
  }
}

void CCS_Allocate_Union_Receiver_Slots(int32u context)
{
  stdit it;
  int32u seq;
  ccs_union_entry *entry;

  /*
   * Iterate through the union hash.  For each union entry, 
   * add the described message to the retransmission list.
   */

  if(context != PENDING_CONTEXT) {
    Alarm(CCS_PRINT, "Called CCS_Allocate_Union_Receiver in non-pending context!\n");
    return;
  }

  Alarm(CCS_PRINT, "CCS: Allocate_Union_Receiver_Slots()\n");
  stdhash_begin(&CCS_UNION.union_data[context], &it);
  
  while(!stdhash_is_end(&CCS_UNION.union_data[context], &it)) {
    Alarm(CCS_PRINT, "Top of union loop.\n");

    seq   = *(int32u *)stdhash_it_key(&it);
    entry = *(ccs_union_entry **)stdhash_it_val(&it);

    if(entry->type == INTERMEDIATE_TYPE) {
      OPENSSL_RSA_Print_Digest(entry->digest);
      
      Alarm(CCS_PRINT, "Finished printing digest.\n");

      PCRCV_Configure_Prepare_Certificate_Receiver(entry->local_view, 
						   entry->global_view, 
						   seq, 
						   entry->digest);

      Alarm(CCS_PRINT, "Finished call to configure.\n");
    }
    stdhash_it_next(&it); 
  }
  
  Alarm(CCS_PRINT, "Finished Allocate_Union\n");

  /*if(PENDING.View == 3)
    Alarm(EXIT, "End of Allocate.\n");
  */
}

void CCS_Description_Handler(signed_message *m)
{
  int32u i, c;
  ccs_description_message *dm = (ccs_description_message *)(m+1);
  description_entry *entry;

  Alarm(DEBUG, "CCS_Description_Handler\n");

  /*
   * Only handle the first description message received in the current
   * view.  If it's the first one, store it.  For each entry in the
   * description, store the server to which it corresponds, and the
   * digest of the associated report message that will be received.
   */

  c  = dm->context;

  if(CCS_REPORTS.Description[c] == NULL) {
    inc_ref_cnt(m);
    CCS_REPORTS.Description[c] = m;

    Alarm(CCS_PRINT, "Storing description message in context %d, with %d "
	  "entries\n", c, dm->num_entries);

    Alarm(CCS_PRINT, "Machine id = %d, lv = %d, gv = %d, my_lv = %d, my_gv = %d\n",
	  m->machine_id, dm->local_view, dm->global_view, 
	  UTIL_Get_View(PENDING_CONTEXT), UTIL_Get_View(GLOBAL_CONTEXT));

    if(dm->num_entries != (2*VAR.Faults+1)) {
      Alarm(CCS_PRINT, "Wrong number of entries: %d\n", dm->num_entries);
      return;
    }

    for(i = 1; i <= dm->num_entries; i++) {
      entry = Get_Description_Entry(dm, i);
    
      CCS_REPORTS.report_in_description[c][entry->machine_id] = TRUE;
      memcpy(CCS_REPORTS.report_digests[c][entry->machine_id].digest, 
	     entry->digest, DIGEST_SIZE);
      Alarm(CCS_PRINT, "Setting description bit for machine %d\n", 
	    entry->machine_id);
    }
  }
}

int32u Check_Report_Contents(signed_message *m) 
{
  ccs_report_message *report = (ccs_report_message *)(m+1); 
  ccs_global_report_entry  *entry;
  global_slot_struct      *gss;
  pending_slot_struct     *pss;
  proposal_message        *pm;
  pre_prepare_message     *ppm;
  int32u i;

  /*
   * Determine if the server has received all messages described in
   * the report message.
   *
   * Go through each entry in the report message.  If the entry is for
   * an ordered type, then if the data structure slot contains
   * something ordered, we're ok  Otherwise, the predicate is not
   * satisfied.
   *
   * If the entry is for an intermediate type, then if the data
   * structure slot contains something ordered, or something
   * intermediate from a higher view, ok.
   */

  Alarm(DEBUG, "Check_Report_Contents num_entries = %d\n", 
	report->num_entries);

  for(i = 1; i <= report->num_entries; i++) {
    entry = Get_Report_Entry(report, i);

    if(report->context == GLOBAL_CONTEXT) {
      gss = UTIL_Get_Global_Slot_If_Exists(entry->seq);

      /* If I have nothing in this slot*/
      if(gss == NULL)
	return FALSE;
     
      if(entry->type == ORDERED_TYPE)
	if(!UTIL_Is_Globally_Ordered(entry->seq))
	  return FALSE;

      if(entry->type == INTERMEDIATE_TYPE) {
	if(UTIL_Is_Globally_Ordered(entry->seq))
	  continue;
	else if(Is_Global_Slot_Intermediate(gss)) {
	  pm = (proposal_message *)(gss->proposal+1);

	  if(pm->global_view >= entry->global_view)
	    continue;
	}
	return FALSE; /* Predicate not satisfied */
      }
    }
    else if(report->context == PENDING_CONTEXT) {
      pss = UTIL_Get_Pending_Slot_If_Exists(entry->seq);

      /* If I have nothing in this slot*/
      if(pss == NULL)
	return FALSE; 
      
      if(entry->type == ORDERED_TYPE)
	if(!UTIL_Is_Pending_Proposal_Ordered(entry->seq))
	  return FALSE;
      
      if(entry->type == INTERMEDIATE_TYPE) {
	if(UTIL_Is_Pending_Proposal_Ordered(entry->seq))
	  continue;
	else if(Is_Pending_Slot_Intermediate(pss)) {
	  ppm=(pre_prepare_message *)(pss->prepare_certificate.pre_prepare+1);
	  
	  if((ppm->global_view == entry->global_view) &&
	     (ppm->local_view  >= entry->local_view))
	    continue;
	}
	return FALSE; /* Predicate not satisfied */
      }
    }
  }
  return TRUE;
}

void CCS_Begin_Collection_Phase(int32u context)
{
  /*
   * 1. Compute the Union, which updates the CCS_UNION data structure.
   *    Specifically, it fills the hash with entries reflecting the
   *    information needed for the union.
   * 
   * 2. See if I have everything I need, and take appropriate action.
   *    If not, then CCS_Union_Decider() acts as a callback function for
   *    when I do get everything (if ever).
   */

  Alarm(DEBUG, "Changed state to COLLECTING UNION CONTENTS from %d\n", 
	CCS_STATE.State[context]);

  /* Since I've received the description and reports described, stop 
   * sending my report and contents.*/
  UTIL_RETRANS_Clear(&CCS_RETRANS[context]);


  CCS_STATE.State[context] = COLLECTING_UNION_CONTENTS;

  Alarm(DEBUG, "CCS_Begin_Collection_Phase()\n");

  Union(context);

  if(context == PENDING_CONTEXT)
    CCS_Allocate_Union_Receiver_Slots(context);

  if(context == PENDING_CONTEXT)
    Alarm(CCS_PRINT, "Finished (again) allocate union\n");

  CCS_Union_Decider(context);

  Alarm(CCS_PRINT, "Finished Union_Decider from Begin_Collection\n");
}

void CCS_Union_Decider(int32u context)
{
  int32u ret;
  signed_message *union_share;

  /*
   * This function should be called whenever the aru is increased and 
   * whenever something that may be in the union is received.
   */

  if(CCS_STATE.State[context] != COLLECTING_UNION_CONTENTS)
    return;

  /* Returns the number of unsatisfied entries in the union */
  ret = Mark_Union_Entries(context);
  
  if((My_ARU_Is_Sufficient(context)) && (ret == 0)) {
    union_share = CCS_Construct_Threshold_Share(context);
    THRESH_Invoke_Threshold_Signature(union_share);
    dec_ref_cnt(union_share);
    CCS_STATE.State[context] = COLLECTING_SIG_SHARES;
    
    if(context == PENDING_CONTEXT)
      Alarm(CCS_PRINT, "Reached COLLECTING_SIG_SHARES in Pending context.\n");
  }
}

int32u CCS_Am_I_Constrained_In_Pending_Context()
{
  int32u ret;

  if(CCS_STATE.State[PENDING_CONTEXT] == COLLECTING_SIG_SHARES)
    ret = TRUE;
  else
    ret = FALSE;

  return ret;
}


void Union(int32u c)
{
  int32u i, j;
  signed_message          *m;
  ccs_report_message       *report;
  ccs_global_report_entry  *entry;
  ccs_union_entry          *u_entry;
  stdit it;
  int32u add_flag = FALSE;

  /* 
   * Assumption: this server has received the representative's
   * ccs_reports_description_message, and has received the 2f+1
   * ccs_Report messages described in the description.
   *
   * Go through each report message in the description.  For each entry in
   * the current report:
   *
   * 1. If there is no data yet in the union for this sequence number,
   *    include a new entry, regardless of type.
   *
   * 2. If there is an existing entry: 
   *     a. If the potential entry is an intermediate type, replace what 
   *        exists currently if it is also of an intermediate type, and the 
   *        potential one is from a higher view.
   *
   *     b. If the potential entry is an ordered type, replace what exists
   *        currently if it is either of an intermediate type, or if the 
   *        potential is of a higher view than the current ordered one.   
   */

  Alarm(CCS_PRINT, "CCS: Union()\n");

  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    /*
     * If this server's report is to be used in the union (i.e. it is in the 
     * description message), process the contents of the report message.
     */
    Alarm(CCS_PRINT,"REPORT for server: %d\n",i);
  
   if(CCS_REPORTS.report_in_description[c][i]) {
      m = CCS_REPORTS.Report_List[c][i];

      if(m == NULL) {
	Alarm(CCS_PRINT, "Unexpected: m is NULL\n");
	return;
      }

      report = (ccs_report_message *)(m+1);
      if(report == NULL) {
	Alarm(CCS_PRINT, "Unexpected: report is NULL.\n");
	return;
      }
      

      Alarm(CCS_PRINT, "Num_Report_Entries from server %d's report: %d\n", 
	    i, report->num_entries); 
      for(j = 1; j <= report->num_entries; j++) {
	add_flag = FALSE;
	
	entry = Get_Report_Entry(report, j);
	Alarm(CCS_PRINT, "Entry: %d\n", entry);
	stdhash_find(&(CCS_UNION.union_data[c]), &it, &entry->seq);

	/* If the slot is empty, store this message */
	if(stdhash_is_end(&CCS_UNION.union_data[c], &it)) {
	  u_entry = Get_New_Union_Entry();

	  u_entry->type        = entry->type;
	  u_entry->local_view  = entry->local_view;
	  u_entry->global_view = entry->global_view;
	  
	  u_entry->marked = FALSE;

	  Alarm(CCS_PRINT, "Seq %d, Type %d", entry->seq, entry->type );

	  if(entry->type == INTERMEDIATE_TYPE && 
	     report->context == PENDING_CONTEXT )
	    Alarm(CCS_PRINT, "Added the prepare certificate to empty union.\n");


	  if(report->context == PENDING_CONTEXT) {
	    memcpy(u_entry->digest, 
		   ((ccs_pending_report_entry *)entry)->digest,
		   DIGEST_SIZE);
	  }
	  
	  stdhash_insert(&(CCS_UNION.union_data[c]), &it, 
			 &entry->seq, &u_entry);
	  CCS_UNION.num_entries_remaining[c]++;
	}

	else {
	  u_entry = *(ccs_union_entry **)stdhash_it_val(&it);
	
	  if(entry->type == INTERMEDIATE_TYPE) {
	    if(u_entry->type == INTERMEDIATE_TYPE) {
	      
	      /*
	       * I consider adding an INTERMEDIATE type when an INTERMEDIATE
	       * entry already exists in the hash.  In this case, I will only
	       * replace the one I have if the new one is from a later view.
	       */
	      if(report->context == PENDING_CONTEXT) {
		if((entry->global_view == u_entry->global_view) && 
		   (entry->local_view  > u_entry->local_view))
		  add_flag = TRUE;
	      }
	      else if(report->context == GLOBAL_CONTEXT) {
		if(entry->global_view > u_entry->global_view)
		  add_flag = TRUE;
	      }
	      
	      /* If I'm "adding" it, update the existing entry */
	      if(add_flag) {
		u_entry->type        = INTERMEDIATE_TYPE;
		u_entry->local_view  = entry->local_view;
		u_entry->global_view = entry->global_view;
		u_entry->marked      = FALSE;

		Alarm(CCS_PRINT, "Seq %d, Type %d", entry->seq, entry->type );

		if(report->context == PENDING_CONTEXT) {

		  Alarm(CCS_PRINT, "Adding an intermediate entry to union, "
			"seq: %d\n", entry->seq);

		  memcpy(u_entry->digest, 
			 ((ccs_pending_report_entry *)entry)->digest,
			 DIGEST_SIZE);
		}
	      }
	    }
	  }
	  
	  /*
	   * Insert an entry for an ordered item if it replaces an
	   * intermediate item, or it is newer than an existing
	   * ordered item.
	   */
	  else if(entry->type == ORDERED_TYPE) {
	    if(u_entry->type == INTERMEDIATE_TYPE) {
	      add_flag = TRUE;

	      if(report->context == PENDING_CONTEXT)
		Alarm(CCS_PRINT, "Overwriting intermediate entry with ordered.\n");
	    }
	    else {
	      if(report->context == PENDING_CONTEXT) {
		if((entry->global_view == u_entry->global_view) && 
		   (entry->local_view  > u_entry->local_view))
		  add_flag = TRUE;
	      }
	      else if(report->context == GLOBAL_CONTEXT) {
		if(entry->global_view > u_entry->global_view)
		  add_flag = TRUE;
	      }

	      if(add_flag) {
		u_entry->type        = ORDERED_TYPE;
		u_entry->local_view  = entry->local_view;
		u_entry->global_view = entry->global_view;
		u_entry->marked      = FALSE;

		Alarm(CCS_PRINT, "Seq %d, Type %d", entry->seq, entry->type );
	      }
	    }
	  }
	}
      }
    }
  }

  
  /*if(PENDING.View == 3)*/
    Alarm(DEBUG, "End of Union\n");
}


/* Returns the number of entries still unfulfilled*/
int32u Mark_Union_Entries(int32u context)
{
  stdit it;
  ccs_union_entry *entry;
  int32u seq;
  global_slot_struct  *gss;
  pending_slot_struct *pss;
  proposal_message    *pm;
  pre_prepare_message *ppm;

  Alarm(DEBUG, "CCS: Mark_Union_Entries()\n");
  stdhash_begin(&CCS_UNION.union_data[context], &it);

  while(!stdhash_is_end(&CCS_UNION.union_data[context], &it)) {
    seq   = *(int32u *)stdhash_it_key(&it);
    entry = *(ccs_union_entry **)stdhash_it_val(&it);

    if(context == GLOBAL_CONTEXT) {
      gss = UTIL_Get_Global_Slot_If_Exists(seq);

      if(gss == NULL) {
	Alarm(DEBUG, "CONTINUING, global \n"); 
	stdhash_it_next(&it);
	continue;
      }

      /*Alarm(EXIT, "Unexpected empty global slot in Mark_Union_Entries, "
	      "seq = %d\n", seq);*/

      if(UTIL_Is_Globally_Ordered(seq)) {
	if(entry->marked == FALSE) {
	  entry->marked = TRUE;
	  CCS_UNION.num_entries_remaining[context]--;
	}
      }
      else if(Is_Global_Slot_Intermediate(gss)) {
	pm = (proposal_message *)(gss->proposal+1);

	if((entry->type == INTERMEDIATE_TYPE) && 
	   (pm->global_view >= entry->global_view)) {
	  if(entry->marked == FALSE) {
	    entry->marked = TRUE;
	    CCS_UNION.num_entries_remaining[context]--;
	  }
	}
      }
    }
    else if(context == PENDING_CONTEXT) {
      pss = UTIL_Get_Pending_Slot_If_Exists(seq);
      
      if(pss == NULL) {
	Alarm(DEBUG, "CONTINUING, pending \n");
	stdhash_it_next(&it);
	continue; 
      }
      /*Alarm(EXIT, "Unexpected empty pending slot in Mark_Union_Entries, "
	"seq = %d\n", seq);*/

      if(UTIL_Is_Pending_Proposal_Ordered(seq)) {
	pm = (proposal_message *)(pss->proposal + 1);

	if((entry->global_view == pm->global_view) &&
	   (pm->local_view >= entry->local_view)) {
	  if(entry->marked == FALSE) {
	    entry->marked = TRUE;
	    CCS_UNION.num_entries_remaining[context]--;
	  }
	}
      }
      else if(Is_Pending_Slot_Intermediate(pss)) {
	ppm = (pre_prepare_message *)(pss->prepare_certificate.pre_prepare+1);
	
	if(entry->type == INTERMEDIATE_TYPE) {
	  if((entry->global_view == ppm->global_view) &&
	     (ppm->local_view >= entry->local_view)) {
	    if(entry->marked == FALSE) {
	      entry->marked = TRUE;
	      CCS_UNION.num_entries_remaining[context]--;
	    }
	  }
	}
      }
    }
    stdhash_it_next(&it); 
  }  
  return CCS_UNION.num_entries_remaining[context];
}

/* Meta protocol */


/* When a union messsage is created when enough sig shares are received, this
 * function will be called upon. */
void CCS_Handle_Union_Message( signed_message *new_ccs_union ) {

    ccs_union_message *union_specific;

    union_specific = (ccs_union_message*)(new_ccs_union+1);

    /* If the context is global, we must send the union message on the
     * wide area.  NOTE: We could try to send only to the leader site
     * if this ccs * union message is from a non_leader site (ie it is
     * a prepare-ok ) */
    if ( union_specific->context == GLOBAL_CONTEXT ) {
      Alarm(CCS_PRINT, "Handle_CCS_Union_Message\n");

      /* Everyone sends the ccs_union */
      UTIL_RETRANS_Add_Message(&CCS_GLOBAL_RETRANS, new_ccs_union);

      /* Leader site stores it */
      if ( UTIL_I_Am_In_Leader_Site() ) {
	/* FINAL we changed this so the leader site doesn't just send the 
	 * message to himself. */
	CCS_GLOBAL_RETRANS.type = UTIL_RETRANS_TO_SERVERS_WITH_MY_ID;
	inc_ref_cnt( new_ccs_union );
	GLOBAL_CCS_UNION[ VAR.My_Site_ID ] = new_ccs_union;
      }
      else {
	/* Non-leader site sends the contents, too.*/
	  /* FINAL -- added next line */
	CCS_GLOBAL_RETRANS.type = UTIL_RETRANS_TO_LEADER_SITE_REP;
	UTIL_RETRANS_Add_Message(&CCS_GLOBAL_RETRANS, new_ccs_union);
	/*UTIL_Send_To_Site_Servers_With_My_ID(new_ccs_union);*/
	
	/* Adds the union contents to the retransmission list */
	Send_Global_Union_Contents_To_Leader_Site(new_ccs_union);
      }
      
      /* Go! */
      UTIL_RETRANS_Start(&CCS_GLOBAL_RETRANS);
    }      
    /* We don't need to send PENDING */
}

int32u CCS_Is_Union_Message_Satisfied( signed_message *ccs_union ) 
{
  ccs_union_message *union_specific;
  ccs_global_report_entry *entry, *base;
  global_slot_struct *gss;
  proposal_message *proposal_specific;
  int32u num_entries, i;

  if ( ccs_union == NULL )
    return 0;
  
  /* 
   * This function is called in the global context by the servers in the 
   * leader site upon receiving the Prepare_OK (union) message from 
   * non-leader sites.  It returns true if this server has at least as
   * much in its data structure as is described in the computed union,
   * and false otherwise.
   */

  union_specific = (ccs_union_message *)(ccs_union + 1);

  if(GLOBAL.ARU < union_specific->aru) {
    Alarm(DEBUG, "Union message not satisfied, bad ARU. %d %d\n",
	  GLOBAL.ARU, union_specific->aru);
    return 0;
  }
  
  num_entries = ( (ccs_union->len - sizeof(ccs_union_message)) / 
		  sizeof(ccs_global_report_entry) );
  
  for(i = 0; i < num_entries; i++) {
    base  = (ccs_global_report_entry *)(union_specific + 1);
    entry = (ccs_global_report_entry *)(base + i);
    
    gss = UTIL_Get_Global_Slot_If_Exists(entry->seq);

    /* If I have nothing in this slot*/
    if(gss == NULL)
      return 0;
     
    if(entry->type == ORDERED_TYPE)
      if(!UTIL_Is_Globally_Ordered(entry->seq))
	return 0;

    if(entry->type == INTERMEDIATE_TYPE) {
      if(UTIL_Is_Globally_Ordered(entry->seq))
	continue;
      else if(Is_Global_Slot_Intermediate(gss)) {
	proposal_specific = (proposal_message *)(gss->proposal+1);

	if(proposal_specific->global_view >= entry->global_view)
	  continue;
      }
      return 0; /* Predicate not satisfied */
    }
  }
  
  return 1;
}

void Send_Global_Union_Contents_To_Leader_Site(signed_message *ccs_union)
{
  ccs_union_message *union_specific;
  ccs_global_report_entry *entry, *base;
  global_slot_struct *gss;
  int32u num_entries, i;

  if( ccs_union == NULL ) {
    Alarm(CCS_PRINT, "Unexpected: Send_Global_Union_Contents empty union mess.\n");
    return;
  }

  union_specific = (ccs_union_message *)(ccs_union + 1);
  
  num_entries = ( (ccs_union->len - sizeof(ccs_union_message)) / 
		  sizeof(ccs_global_report_entry) );
  
  for(i = 0; i < num_entries; i++) {
    base  = (ccs_global_report_entry *)(union_specific + 1);
    entry = (ccs_global_report_entry *)(base + i);
    
    gss = UTIL_Get_Global_Slot_If_Exists(entry->seq);
    
    /* If I have nothing in this slot*/
    if(gss == NULL) {
      Alarm(CCS_PRINT, "Unexpected: Send_Global_Union_Contents no slot\n");
      return;
    }     

    if(entry->type == ORDERED_TYPE) {
      /* Ordered in global context.*/
      Alarm(CCS_PRINT, "Unexpected: Send_Global_Union_Contents, tried to send "
	    "ordered entry.\n");
      return;
    }
    else if(entry->type == INTERMEDIATE_TYPE) {
      UTIL_RETRANS_Add_Message(&CCS_GLOBAL_RETRANS, gss->proposal);

    }
  }
}

int32u CCS_Is_Globally_Constrained() {

    int32u si;
    int32u count;

    /* If we're already globally constrained in this global view, true*/
    if(CCS_last_globally_constrained_view == GLOBAL.View)
      return 1;
    
    /* Otherwise, see if we can set our flag for the first time based on
     * how many completed union messages we have.  If enough, true, and 
     * set the flag to remember for next time.*/
    count = 0;
    for ( si = 1; si <= NUM_SITES; si++ ) {
	if ( CCS_Is_Union_Message_Satisfied ( GLOBAL_CCS_UNION[si] ) ) {
	    count++;
	}
    }    

    if ( count >= (NUM_SITES / 2) + 1) {
      CCS_last_globally_constrained_view = GLOBAL.View;
      return 1;
    }
    
    /* Predicate not satisfied */
    return 0;
}

void CCS_Forward_Union_Message( signed_message *ccs_union ) {

    ccs_union_message *union_specific;

    union_specific = (ccs_union_message*)(ccs_union+1);

    util_stopwatch *sw;

    sw = &UNION_FORWARD_STOPWATCH[ccs_union->site_id];  

    UTIL_Stopwatch_Stop( sw );

    if ( UTIL_Stopwatch_Elapsed( sw ) > 0.050 ) {
	/* Forward the message to everyone in my site */
	UTIL_Site_Broadcast( ccs_union );
	UTIL_Stopwatch_Start( sw );
    }

}

void CCS_Process_Union_Message( signed_message *ccs_union ) {

    ccs_union_message *union_specific;

    union_specific = (ccs_union_message*)(ccs_union+1);

    
    Alarm(CCS_PRINT, "Union_Message from site %d, aru=%d, gv=%d, my_gv=%d\n",
	  ccs_union->site_id, union_specific->aru, union_specific->global_view,
	  GLOBAL.View);
    
    if ( union_specific->context != GLOBAL_CONTEXT ) {
	return;
    }

    if ( union_specific->global_view != GLOBAL.View ) {
	return;
    }

    /* FINAL -- commented following conditional out */
#if 0
    if ( ccs_union->site_id == VAR.My_Site_ID ) {
      return;
    }
#endif


    if(UTIL_I_Am_In_Leader_Site() && VAR.My_Site_ID == 2) {

      Alarm(DEBUG, "Got a Union message from site %d.\n", ccs_union->site_id);
    }

    CCS_Is_Globally_Constrained();

    if ( UTIL_I_Am_In_Leader_Site() ) {
	/* This corresponds to a prepare-ok messsage */
	/* Store it */
	if ( GLOBAL_CCS_UNION[ ccs_union->site_id ] != NULL ) {
	   dec_ref_cnt( GLOBAL_CCS_UNION[ ccs_union->site_id ] );
	}
	GLOBAL_CCS_UNION[ ccs_union->site_id ] = ccs_union;
	inc_ref_cnt( ccs_union );
	CCS_Is_Globally_Constrained();
	CCS_Forward_Union_Message( ccs_union );
    } else {
      /* This message corresponds to a Prepare message.*/

      if( ccs_union->site_id == UTIL_Leader_Site() ) {
      /* FINAL --- we do need to forward it to everyone in our site. */
        CCS_Forward_Union_Message( ccs_union );
	/* If I haven't stored a target aru for this global view,
	 * store it now and try to invoke.  NOTE: This will only be called
	 * from this function the first time.  Subsequent attempts to invoke
	 * CCS will be triggered by the callback function. */

	/* FINAL Changed GLOBAL.View to PENDING.View*/
	if(CCS_global_target_aru_last_set_in_view < PENDING.View) {
	  CCS_global_target_aru_last_set_in_view = PENDING.View;
	  CCS_global_target_aru = union_specific->aru;

	  CCS_Global_Response_Decider();
	}
      }
    }
}
      
#if 0
	/* Do a global reconciliation to bring the representative up to
	 * date with the aru in the ccs union message. */
	
	/* FORCE GLOBAL RECONCILIATION */
	
	if ( UTIL_I_Am_Representative() && 
	     ccs_union->site_id == UTIL_Leader_Site()  ) {
	  Alarm(DEBUG,"%d %d INVOKING CCS\n",
		VAR.My_Site_ID, VAR.My_Server_ID );
	  CCS_Send_Invocation_Message( GLOBAL_CONTEXT,
				      union_specific->aru );
	}
#endif

void CCS_Global_Response_Decider()
{
  /* If I'm the representative of a non-leader site, and I've received
   * an appropriate CCS_Union message from the leader site and set my
   * corresponding view and aru fields, and my aru is at least as high
   * as the one sent in the union message, I can invoke CCS in the
   * global context.*/


  /* FINAL Changed GLOBAL.View to PENDING.View */
  if( UTIL_I_Am_Representative() && !UTIL_I_Am_In_Leader_Site() &&
      CCS_global_target_aru_last_set_in_view == PENDING.View) {

    if( UTIL_Get_ARU(GLOBAL_CONTEXT) >= CCS_global_target_aru ) {
      Alarm(CCS_PRINT,"%d %d INVOKING CCS in Global context\n", 
	    VAR.My_Site_ID, VAR.My_Server_ID );
      CCS_Send_Invocation_Message( GLOBAL_CONTEXT, CCS_global_target_aru );
    }
    else {
      /* Set up a reconciliation session to bring myself up to the ccs 
       * target aru.  When my aru meets this value, and this function is
       * called again, the above check will go through and I'll invoke.*/
      GRECON_Start_Reconciliation(CCS_global_target_aru);
    }
  }
}
