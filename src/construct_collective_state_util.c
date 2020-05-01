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

#include "construct_collective_state_util.h"
#include "construct_collective_state_protocol.h"
#include "utility.h"
#include "util/alarm.h"
#include "util/memory.h"
#include "objects.h"
#include "prepare_certificate_receiver.h"
#include <string.h>

extern ccs_state_struct             CCS_STATE;
extern ccs_collected_reports_struct CCS_REPORTS;
extern ccs_union_struct             CCS_UNION;
extern retrans_struct               CCS_RETRANS[NUM_CONTEXTS];
extern retrans_struct               CCS_GLOBAL_RETRANS;

extern server_variables    VAR;
extern global_data_struct  GLOBAL;
extern pending_data_struct PENDING;

/* Storage for sig share messages */
extern signed_message *CCS_UNION_SIG_SHARE[NUM_CONTEXTS][NUM_SERVER_SLOTS]; 

/* Storage of actual union messages -- these have valid threshold signatures */
extern signed_message *CCS_UNION_MESSAGE[NUM_CONTEXTS]; 

extern signed_message *GLOBAL_CCS_UNION[NUM_SITES+1];

extern int32u CCS_global_target_aru_last_set_in_view;
extern int32u CCS_global_target_aru;
extern int32u CCS_last_globally_constrained_view;

extern util_stopwatch UNION_FORWARD_STOPWATCH[NUM_SITES+1];


signed_message* Construct_CCS_Invocation( int32u context, int32u aru ) 
{
  signed_message *invocation;
  ccs_invocation_message *invocation_specific;

  /* Construct new message */
  invocation = UTIL_New_Signed_Message();
  
  invocation_specific = (ccs_invocation_message*)(invocation + 1);
  
  invocation->site_id    = VAR.My_Site_ID;
  invocation->machine_id = VAR.My_Server_ID;
  invocation->type       = CCS_INVOCATION_TYPE;
  invocation->len        = sizeof(ccs_invocation_message);

  invocation_specific->context = context;  
  invocation_specific->local_view  = UTIL_Get_View(PENDING_CONTEXT);
  invocation_specific->global_view = UTIL_Get_View(GLOBAL_CONTEXT);
  invocation_specific->aru     = aru; 

  Alarm(DEBUG, "Constructing invocation with aru %d\n", 
	invocation_specific->aru);
  
  /* Compute a standard RSA signature. */
  UTIL_RSA_Sign_Message( invocation );
  
  return invocation;
}


signed_message *Construct_CCS_Report(int32u my_aru, int32u context)
{
  signed_message    *ccs_report;
  ccs_report_message *ccs_report_specific;
  int32u total_report_bytes, size;

  /* Construct new message */
  ccs_report = UTIL_New_Signed_Message();
  ccs_report_specific = (ccs_report_message *)(ccs_report + 1);

  /* Fill in the contents of the message */
  ccs_report->site_id    = VAR.My_Site_ID;
  ccs_report->machine_id = VAR.My_Server_ID;
  ccs_report->type       = CCS_REPORT_TYPE;
  
  ccs_report_specific->context = context;
  ccs_report_specific->local_view  = UTIL_Get_View(PENDING_CONTEXT);
  ccs_report_specific->global_view = UTIL_Get_View(GLOBAL_CONTEXT);
  ccs_report_specific->aru     = my_aru;
  
  total_report_bytes = 
    Construct_CCS_Report_List((byte *)(ccs_report_specific+1),
			      my_aru, context);
  
  size = 0;
  if(context == GLOBAL_CONTEXT)
    size = sizeof(ccs_global_report_entry);
  else if(context == PENDING_CONTEXT)
    size = sizeof(ccs_pending_report_entry);

  Alarm(CCS_PRINT,"Total report bytes %d\n", total_report_bytes);
  
  ccs_report_specific->num_entries = (total_report_bytes) / size; 
  ccs_report->len = sizeof(ccs_report_message) + total_report_bytes;
 
  UTIL_RSA_Sign_Message(ccs_report);

  Alarm(DEBUG,"Finished constructing ccs report\n");
  
  return ccs_report;
}

int32u Construct_CCS_Report_List(byte *Report_List, int32u my_aru, 
				int32u context)
{
  int32u i;
  int32u total_bytes_so_far = 0;
  ccs_pending_report_entry re;
  pre_prepare_message *ppm;
  proposal_message    *pm;
  global_slot_struct  *gss;
  pending_slot_struct *pss;

  signed_message *pre_prepare;
  pre_prepare_message *pre_prepare_specific;

  /* Sanity */
  if(CCS_STATE.My_Max_Seq_Response[context] > my_aru + GLOBAL_WINDOW+ 5) {
    Alarm(CCS_PRINT, "Trying to report too much, my_aru = %d, my max = %d\n",
	  my_aru, CCS_STATE.My_Max_Seq_Response[context]);
    return 0;
  } 

  for(i = my_aru + 1;  i <= CCS_STATE.My_Max_Seq_Response[context]; i++) {
    if(context == GLOBAL_CONTEXT) {
      gss = UTIL_Get_Global_Slot_If_Exists(i);
      
      /* If nothing in this global slot, skip it. */      
      if(gss == NULL)
	continue;

      else {
	if(UTIL_Is_Globally_Ordered(i)) {
	  pm = (proposal_message *)(gss->proposal + 1);

	  /*re.type        = ORDERED_TYPE;*/
	  re.type        = INTERMEDIATE_TYPE;
	  re.global_view = pm->global_view;
	  re.local_view  = pm->local_view;
	  re.seq         = i;
	}
	else if(Is_Global_Slot_Intermediate(gss)) {
	  pm = (proposal_message *)(gss->proposal + 1);

	  re.type        = INTERMEDIATE_TYPE;
	  re.global_view = pm->global_view;
	  re.local_view  = pm->local_view;
	  re.seq         = i;
	}
	else
	  continue; /* Pre-intermediate, don't report */

	memcpy(&Report_List[total_bytes_so_far], &re, 
	       sizeof(ccs_global_report_entry));
	total_bytes_so_far += sizeof(ccs_global_report_entry);
      }
    }
    else if(context == PENDING_CONTEXT) {
      pss = UTIL_Get_Pending_Slot_If_Exists(i);

      /* If nothing in this pending slot, skip it. */      
      if(pss == NULL)
	continue;

      else {

	UTIL_Purge_Pending_Slot_Seq(i);

	if(UTIL_Is_Pending_Proposal_Ordered(i)) {
	  pm = (proposal_message *)(pss->proposal + 1);

	  re.type        = ORDERED_TYPE;
	  re.global_view = pm->global_view;
	  re.local_view  = pm->local_view;
	  re.seq         = i;
	}
	else if(Is_Pending_Slot_Intermediate(pss)) {
	  ppm =(pre_prepare_message *)(pss->prepare_certificate.pre_prepare+1);

	  re.type        = INTERMEDIATE_TYPE;
	  re.global_view = ppm->global_view;
	  re.local_view  = ppm->local_view;
	  re.seq         = i;
	  
	  Alarm(CCS_PRINT, "Adding prepare certificate to report.\n");
	}
	else 
	  continue; /* Pre-intermediate, don't report */
	
	Alarm(DEBUG, "Adding report entry for seq %d\n", i);
	
	memcpy(&Report_List[total_bytes_so_far], &re, 
	       sizeof(ccs_pending_report_entry) - DIGEST_SIZE);
	
	total_bytes_so_far += (sizeof(ccs_pending_report_entry)-DIGEST_SIZE);

	/*OPENSSL_RSA_Print_Digest(pss->prepare_certificate.update_digest);*/

	pre_prepare = pss->prepare_certificate.pre_prepare;
	pre_prepare_specific = (pre_prepare_message *)(pre_prepare+1);

	OPENSSL_RSA_Make_Digest( (void *)(pre_prepare_specific+1), 
				 pre_prepare->len -sizeof(pre_prepare_message),
				 &Report_List[total_bytes_so_far] );

	total_bytes_so_far += DIGEST_SIZE;
      }
    }
  }
  return total_bytes_so_far;
}

signed_message *Construct_CCS_Description(int32u context)
{
  signed_message *description;
  ccs_description_message *ccs_rd_specific;
  char Description_List[MAX_PACKET_SIZE];
  int32u num_entries;

  /* Construct new message */
  description = UTIL_New_Signed_Message();
  ccs_rd_specific = (ccs_description_message *)(description + 1);

  /* Fill in the contents of the message */
  description->site_id    = VAR.My_Site_ID;
  description->machine_id = VAR.My_Server_ID;
  description->type       = CCS_DESCRIPTION_TYPE;

  ccs_rd_specific->context      = context;
  ccs_rd_specific->local_view   = UTIL_Get_View(PENDING_CONTEXT);
  ccs_rd_specific->global_view  = UTIL_Get_View(GLOBAL_CONTEXT);
 
  num_entries = Construct_CCS_Description_List(Description_List, context);
  memcpy((ccs_rd_specific + 1), Description_List, 
	 num_entries * sizeof(description_entry));

  ccs_rd_specific->num_entries = num_entries;

  description->len = sizeof(ccs_description_message) + 
    (num_entries * sizeof(description_entry));

  UTIL_RSA_Sign_Message(description);

  return description;
}

int32u Construct_CCS_Description_List(char *des_list, int32u context)
{
  int32u i;
  int32u num_entries = 0;
  description_entry de;
  unsigned char digest[DIGEST_SIZE];
  signed_message *report;

  /*
   * Fill in the description list with pairs of the form:
   *     (id, digest)
   * where digest is computed on id's report message in this context.
   */

  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    if(CCS_REPORTS.completed_report_list[context][i]) {
      report = CCS_REPORTS.Report_List[context][i];
      
      OPENSSL_RSA_Make_Digest(report, report->len, digest);  
      
      de.machine_id = i;
      Alarm(DEBUG, "Adding id %d to description list.\n", i);
      memcpy((char *)de.digest, digest, DIGEST_SIZE); 
      memcpy(&des_list[num_entries*sizeof(description_entry)], 
	     &de, sizeof(description_entry));
      num_entries++;
      
      if(num_entries == (2*VAR.Faults+1))
	break;
    }
  }
  
  return num_entries;
}

/* 
 * Returns the number of bytes written, writes the union to buf, and returns
 * the site_aru
 */
int32u Construct_Union_Message_And_ARU(unsigned char *buf, int32u *site_aru, 
				       int32u context)
{
  int32u seq, total_bytes_written;
  ccs_union_entry *union_entry;
  ccs_global_report_entry gre;
  ccs_pending_report_entry pre;
  stdit it;

  total_bytes_written = 0;

  stdhash_begin(&CCS_UNION.union_data[context], &it);

  while(!stdhash_is_end(&CCS_UNION.union_data[context], &it)) {
    seq         = *(int32u *)stdhash_it_key(&it);
    union_entry = *(ccs_union_entry **)stdhash_it_val(&it);

    Alarm(CCS_PRINT, "Top of loop, seq = %d\n", seq);

    if(context == GLOBAL_CONTEXT) {
      /* Pull out the hash entry and set up a record for it in message*/
      gre.type = union_entry->type;
      gre.seq  = seq;
      gre.local_view  = union_entry->local_view;
      gre.global_view = union_entry->global_view;
      
      memcpy(&buf[total_bytes_written], &gre, sizeof(gre));
      total_bytes_written += sizeof(gre);
    }
    else if(context == PENDING_CONTEXT) {
      /* Pull out the hash entry and set up a record for it in message*/
      pre.type = union_entry->type;
      pre.seq  = seq;
      pre.local_view  = union_entry->local_view;
      pre.global_view = union_entry->global_view;
      
      memcpy(&buf[total_bytes_written], &pre, sizeof(pre));
      total_bytes_written += sizeof(pre);
      
      memcpy(&buf[total_bytes_written], union_entry->digest, DIGEST_SIZE);
      total_bytes_written += DIGEST_SIZE;
    }
    stdhash_it_next(&it);
  }
  Alarm(CCS_PRINT, "Finished contstructing.\n");
  return total_bytes_written;
}

signed_message *CCS_Construct_Threshold_Share(int32u context)
{
  int32u start;
  signed_message   *union_share;
  ccs_union_message *union_specific;
  unsigned char    *buf;
  int total_bytes_written;

  Alarm(CCS_PRINT, "Constructing_Threshold_Share in context: %d\n", context);

  union_share    = UTIL_New_Signed_Message();
  union_specific = (ccs_union_message *)(union_share + 1);
  buf            = (unsigned char *)(union_specific + 1);
  
  /* Fill in the contents of the signed message */ 
  union_share->site_id    = VAR.My_Site_ID;
  union_share->machine_id = 0; /* So everyone matches...*/
  union_share->type       = CCS_UNION_TYPE;
  
  /* Fill in the conents of the union message */
  union_specific->context     = context;
  union_specific->local_view  = UTIL_Get_View(PENDING_CONTEXT); 
  union_specific->global_view = UTIL_Get_View(GLOBAL_CONTEXT);
 
  start = Get_Max_ARU(context);
 
  /* Updates buf and site_aru */
  total_bytes_written = Construct_Union_Message_And_ARU(buf, &start, context);
  Alarm(CCS_PRINT, "Total union bytes written: %d\n", total_bytes_written);

  union_specific->aru = start;
  union_share->len    = sizeof(ccs_union_message) + total_bytes_written;     

  Alarm(DEBUG, "----------------\n");
  Alarm(DEBUG, "Context: %d\n", union_specific->context);
  Alarm(DEBUG, "ARU: %d\n", union_specific->aru);
  Alarm(DEBUG, "Local_View: %d\n", union_specific->local_view);
  Alarm(DEBUG, "Global_View: %d\n", union_specific->global_view);
  Alarm(DEBUG, "----------------\n");
  
  return union_share; 
}                  



void Send_Report_Contents(int32u rep_id, signed_message *m)
{
  ccs_report_message      *report;
  ccs_global_report_entry *entry;
  global_slot_struct     *gss;
  pending_slot_struct    *pss;
  prepare_message  *prepare_specific;
  int32u i, j;
  int32u pc_count;

  report = (ccs_report_message *)(m+1); 

  /*
   * Grab the appropriate data structure slot, depending on context.
   * Then send the corresponding signed message.
   */
  
  for(i = 1; i <= report->num_entries; i++) {
    
    entry = Get_Report_Entry(report, i);
    if ( entry == NULL ) {
      Alarm(CCS_PRINT,"CCS_Send_Report_Contents ENTRY NULL\n");
      return;
    }    

    if(report->context == PENDING_CONTEXT) {
      pss = UTIL_Get_Pending_Slot_If_Exists(entry->seq);
      
      if ( pss == NULL ) {
	Alarm(CCS_PRINT,"CCS_Send_Report_Contents pss NULL\n");
	return;
      }
      
      if(entry->type == ORDERED_TYPE) {
	
	/* Sanity */   
	if(pss->proposal == NULL) {
	  Alarm(CCS_PRINT, "Send_Report_Contents: claimed to have ORDERED"
		"entry in global context but don't have Proposal in slot.\n");
	  return;
	}

	/* Sanity */   
	if ( ((proposal_message*)(pss->proposal+1))->global_view 
	     != GLOBAL.View ) {
	  Alarm(CCS_PRINT,"CCS_Send_Report_Contents Tried to send "
		"a proposal that is not in my global view. %d %d %d\n",
	  ((proposal_message*)(pss->proposal+1))->global_view,
	  ((proposal_message*)(pss->proposal+1))->seq_num,
       	  ((proposal_message*)(pss->proposal+1))->local_view );
	  return;
	}
	
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[report->context], 
				 pss->proposal); 
      }
      
      if(entry->type == INTERMEDIATE_TYPE) {
	/* 
	 * Add Prepare certificate to list to send.  Note that the digest of
	 * the update is included in the report entry and does not require
	 * a separate messsage.
	 */

	/* If I claim to have an intermediate type, I better have a
	 * pre_prepare at least*/
	if ( pss->prepare_certificate.pre_prepare == NULL ) {
	  Alarm(CCS_PRINT,"CCS_Send_Report_Contents: tried to send "
		"null pre_preprare.\n");
	}
	
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[report->context], 
				 pss->prepare_certificate.pre_prepare); 
	
	Alarm(CCS_PRINT, "Reporting a Prepare Certificate for seq: %d\n", 
	      entry->seq);
	
	pc_count = 0;
	for(j = 1; j <= NUM_SERVERS_IN_SITE; j++){
	  if ( pss->prepare_certificate.prepare[j] != NULL ) {
	    UTIL_RETRANS_Add_Message(&CCS_RETRANS[report->context],
				     pss->prepare_certificate.prepare[j]);

	    prepare_specific = 
	      (prepare_message *)(pss->prepare_certificate.prepare[j] + 1);

	    Alarm(CCS_PRINT, "Sending prepare for server %d from lv %d "
		  "and gv %d\n", j, 
		  prepare_specific->local_view, 
		  prepare_specific->global_view);
	    pc_count++;	
	  }
	}
	if ( pc_count < NUM_FAULTS * 2 ) {
	  /* Sanity */
	  Alarm(CCS_PRINT,"CCS_Send_Report_Contents: "
		"didn't send enough preprares.\n");
	}
      }
    }
    else if(report->context == GLOBAL_CONTEXT) {
      gss = UTIL_Get_Global_Slot_If_Exists(entry->seq);
      
      /* check if gss is null */
      if ( gss == NULL ) {
	Alarm(CCS_PRINT,"CCS_Send_Report_Contents gss NULL\n");
	return;
      }
      
      if( entry->type == ORDERED_TYPE ||
	  entry->type == INTERMEDIATE_TYPE ) {
	/* We could send an ordered proof message -- temporarily we will
	 * send only a proposal and then replay if necessary */ 
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[report->context], 
				 gss->proposal);
      }
    }
  }
}

void Send_Described_Reports(signed_message *m)
{
  int32u i;
  ccs_description_message *description = (ccs_description_message *)(m+1);
  description_entry *entry;
  signed_message *report;

  for(i = 1; i <= description->num_entries; i++) {
    entry  = Get_Description_Entry(description, i);
    report = CCS_REPORTS.Report_List[description->context][entry->machine_id];
    
    if(report == NULL) {
      Alarm(CCS_PRINT, "Claimed to set a bit for machine %d, "
	    "but report was NULL\n",
	    entry->machine_id);
      return;
    }
    Alarm(CCS_PRINT, "Rep set description bit for machine %d\n", 
	  entry->machine_id);

    CCS_REPORTS.report_in_description[description->context][entry->machine_id]
      = 1;

    UTIL_RETRANS_Add_Message(&CCS_RETRANS[description->context], report);
  }
}

void Send_Union_Contents(int32u context)
{
  stdit it;
  int32u seq;
  ccs_union_entry *entry;
  int32u i;

  /*
   * Iterate through the union hash.  For each union entry, 
   * add the described message to the retransmission list.
   */

  Alarm(CCS_PRINT, "CCS: Send_Union_Contents()\n");
  stdhash_begin(&CCS_UNION.union_data[context], &it);
  
  while(!stdhash_is_end(&CCS_UNION.union_data[context], &it)) {
    seq   = *(int32u *)stdhash_it_key(&it);
    entry = *(ccs_union_entry **)stdhash_it_val(&it);

    if(context == GLOBAL_CONTEXT) {
      global_slot_struct *gss = UTIL_Get_Global_Slot_If_Exists(seq);

      if(gss == NULL) {
	Alarm(CCS_PRINT, "Unexpected empty slot in Send_Union_Contents!\n");
	return;
      }

      if(entry->type == ORDERED_TYPE) {
	Alarm(CCS_PRINT,"Send_Union_Contents: ORDERED_TYPE shouldn't be "
	      "found!!\n");
	return;
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], gss->proposal);

	for(i = 1; i <= NUM_SERVERS_IN_SITE; i++){
	  UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], gss->accept[i]);
	}
      }
      else if(entry->type == INTERMEDIATE_TYPE) {
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], gss->proposal);
      }
    }
    else if(context == PENDING_CONTEXT) {
      pending_slot_struct *pss = UTIL_Get_Pending_Slot_If_Exists(seq);

      if(pss == NULL) {
	Alarm(CCS_PRINT, "Unexpected empty slot in Send_Union_Contents!\n");
	return;
      }

      if(entry->type == ORDERED_TYPE)
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], pss->proposal); 

      if(entry->type == INTERMEDIATE_TYPE) {
	/* 
	 * Add Prepare certificate to list to send.  Note that the digest of
	 * the update is included in the report entry and does not require
	 * a separate messsage.
	 */
	UTIL_RETRANS_Add_Message(&CCS_RETRANS[context], 
				 pss->prepare_certificate.pre_prepare); 

	if ( pss->prepare_certificate.pre_prepare == NULL ) {

	  if(pss->proposal != NULL) {
	    Alarm(CCS_PRINT, "CCS_Send_Union would say non pre_prepare, "
		  "but I have a proposal.\n");
	    return;
	  }
	  else {
	    Alarm(CCS_PRINT,"CCS_Send_Union_Contents Tried to send "
		  "a pre_preapre that is NULL.\n");
	    return;
	  }
	}
	Alarm(CCS_PRINT, "Sending Prepare Certificate in Union for seq: %d\n", 
	      seq);

	for(i = 1; i <= NUM_SERVERS_IN_SITE; i++){
	  UTIL_RETRANS_Add_Message(&CCS_RETRANS[context],
				   pss->prepare_certificate.prepare[i]);
	   if ( pss->prepare_certificate.prepare[i] == NULL ) {
	       Alarm(CCS_PRINT,"CCS_Send_Union_Contents Tried to send "
		   "a prepare that is NULL.\n");
	   }
	}
      }
    }
    stdhash_it_next(&it); 
  }
}

int32u Get_Max_ARU(int32u context)
{
  int i;
  int32u aru = 0;
  signed_message *m;
  ccs_report_message *report;
 
  /*
   * Look at each of the 2f+1 report messages used in the union and
   * return the highest one.
   */
  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    if(CCS_REPORTS.report_in_description[context][i]) {
      m      = CCS_REPORTS.Report_List[context][i];
      report = (ccs_report_message *)(m+1);

      if(report->aru > aru)
        aru = report->aru;
    }
  }
  return aru;
}

int32u My_ARU_Is_Sufficient(int32u context)
{
  int i;
  int32u my_aru;
  signed_message *m;
  ccs_report_message *report;
  int32u ret = TRUE;

  /*
   * Look at each of the 2f+1 report messages used in the union.  If my_aru
   * is at least as high as all of them, return TRUE.  Otherwise return FALSE.
   */

  Alarm(DEBUG, "CCS My_ARU_Is_Sufficient\n");
  my_aru = UTIL_Get_ARU(context);
  
  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    if(CCS_REPORTS.report_in_description[context][i]) {
      m      = CCS_REPORTS.Report_List[context][i];
      report = (ccs_report_message *)(m+1);
      
      if(my_aru < report->aru) {
        ret = FALSE;
        break;
      }
    }
  }
  return ret;
}


ccs_global_report_entry *Get_Report_Entry(ccs_report_message *report, int32u i)
{
  ccs_global_report_entry *ret = NULL;

  if(report->context == GLOBAL_CONTEXT) {
    ccs_global_report_entry *gre = (ccs_global_report_entry *)(report + 1);
    ret = gre + (i - 1);
  }
  else if(report->context == PENDING_CONTEXT) {
    ccs_pending_report_entry *pre = (ccs_pending_report_entry *)(report+1);
    pre = (pre + (i - 1));
    ret = (ccs_global_report_entry *)pre;
  }
  
  return ret;
}

description_entry *Get_Description_Entry(ccs_description_message *description,
					 int32u i)
{
  description_entry *ret = NULL;

  ret = (description_entry *)(description + 1);
  ret = (description_entry *)(ret + (i - 1));

  return ret;
}

ccs_union_entry *Get_New_Union_Entry()
{
  ccs_union_entry *entry;

  if((entry = (ccs_union_entry *)new_ref_cnt(UNION_ENTRY_OBJ)) == NULL) 
    Alarm(EXIT, "CCS Get_New_Union_Entry(): Could not allocate memory.\n");

  return entry;
}

void CCS_Initialize() {

  int32u si;

  stdhash_construct( &CCS_UNION.union_data[GLOBAL_CONTEXT], sizeof(int32u),
		       sizeof(ccs_union_entry *), UTIL_int_cmp,
		       UTIL_hashcode, 0);

  stdhash_construct( &CCS_UNION.union_data[PENDING_CONTEXT], sizeof(int32u),
		       sizeof(ccs_union_entry *), UTIL_int_cmp,
		       UTIL_hashcode, 0);

  Mem_init_object_abort(UNION_ENTRY_OBJ, sizeof(ccs_union_entry), 200, 20);

  UTIL_RETRANS_Construct( &(CCS_RETRANS[PENDING_CONTEXT]) ); 
  UTIL_RETRANS_Construct( &(CCS_RETRANS[GLOBAL_CONTEXT]) ); 
  UTIL_RETRANS_Construct( &(CCS_GLOBAL_RETRANS) );

  CCS_RETRANS[PENDING_CONTEXT].repeat                  = 1;
  CCS_RETRANS[PENDING_CONTEXT].inter_message_time.sec  = 0;
  CCS_RETRANS[PENDING_CONTEXT].inter_message_time.usec = 10000;
  CCS_RETRANS[PENDING_CONTEXT].inter_group_time.sec    = 0;
  CCS_RETRANS[PENDING_CONTEXT].inter_group_time.usec   = 500000;

  CCS_RETRANS[GLOBAL_CONTEXT].repeat                  = 1;
  CCS_RETRANS[GLOBAL_CONTEXT].inter_message_time.sec  = 0;
  CCS_RETRANS[GLOBAL_CONTEXT].inter_message_time.usec = 10000;
  CCS_RETRANS[GLOBAL_CONTEXT].inter_group_time.sec    = 0;
  CCS_RETRANS[GLOBAL_CONTEXT].inter_group_time.usec   = 500000;

  CCS_GLOBAL_RETRANS.repeat                  = 1;
  CCS_GLOBAL_RETRANS.inter_message_time.sec  = 0;
  CCS_GLOBAL_RETRANS.inter_message_time.usec = 5000;
  CCS_GLOBAL_RETRANS.inter_group_time.sec    = 0;
  CCS_GLOBAL_RETRANS.inter_group_time.usec   = 500000; 
  CCS_GLOBAL_RETRANS.type = UTIL_RETRANS_TO_LEADER_SITE_REP;

  CCS_STATE.State[PENDING_CONTEXT] = INITIAL_STATE;
  CCS_STATE.State[GLOBAL_CONTEXT]  = INITIAL_STATE;

  CCS_STATE.My_Max_Seq_Response[PENDING_CONTEXT] = 0;
  CCS_STATE.My_Max_Seq_Response[GLOBAL_CONTEXT]  = 0;

  CCS_STATE.Latest_Invocation_View[PENDING_CONTEXT] = 0;
  CCS_STATE.Latest_Invocation_View[GLOBAL_CONTEXT]  = 0;

  /* Init data structures for storing completed union messages */
  CCS_UNION_MESSAGE[PENDING_CONTEXT] = NULL;
  CCS_UNION_MESSAGE[GLOBAL_CONTEXT]  = NULL;

  for ( si = 1; si <= NUM_SITES; si++ ) {
    GLOBAL_CCS_UNION[si] = NULL;
  }
  
  CCS_global_target_aru_last_set_in_view = 0;
  CCS_global_target_aru = 0;

  CCS_last_globally_constrained_view = 0;

  PCRCV_Clear_Pcert_Array();
}

void CCS_Reset_Data_Structures(int32u context)
{
  int32u i, si;
  stdit it;
  ccs_union_entry *entry;

  Alarm(CCS_PRINT, "Resetting CCS Data Structures in Context %d\n", context);

  CCS_STATE.State[context] = INITIAL_STATE;

  /* Clear out the report metadata */
  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    if(CCS_REPORTS.Report_List[context][i]) {
      dec_ref_cnt(CCS_REPORTS.Report_List[context][i]);
      CCS_REPORTS.Report_List[context][i] = NULL;
    }
    CCS_REPORTS.completed_report_list[context][i] = 0;
  }

  /* Clear out the description metadata */
  CCS_REPORTS.num_reports_collected[context] = 0;
  CCS_REPORTS.num_completed_reports[context] = 0;
  
  if(CCS_REPORTS.Description[context]) {
    dec_ref_cnt(CCS_REPORTS.Description[context]);
    CCS_REPORTS.Description[context] = NULL;
  }
   
  /* Clear out the report digests */
  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
    CCS_REPORTS.report_in_description[context][i] = 0;
    bzero(CCS_REPORTS.report_digests[context][i].digest, DIGEST_SIZE);
  }

  /* Iterate through contents of union hash and clear it */
  stdhash_begin(&CCS_UNION.union_data[context], &it);
  while(!stdhash_is_end(&CCS_UNION.union_data[context], &it)) {
    entry = *(ccs_union_entry **)stdhash_it_val(&it);
    dec_ref_cnt(entry);
    stdhash_it_next(&it); 
  }

  stdhash_clear(&CCS_UNION.union_data[context]);
  
  CCS_UNION.num_entries_remaining[context] = 0;

  UTIL_RETRANS_Clear( &(CCS_RETRANS[context]) ); 

  if(context == GLOBAL_CONTEXT)
    UTIL_RETRANS_Clear(&CCS_GLOBAL_RETRANS);

  if(CCS_UNION_MESSAGE[context] != NULL)
    dec_ref_cnt(CCS_UNION_MESSAGE[context]);
  CCS_UNION_MESSAGE[context] = NULL;

  if(context == GLOBAL_CONTEXT) {
    for ( si = 1; si <= NUM_SITES; si++ ) {
      if ( GLOBAL_CCS_UNION[si] != NULL ) {
	dec_ref_cnt(GLOBAL_CCS_UNION[si]);
      }      
      GLOBAL_CCS_UNION[si] = NULL;
    }
  }

  for(si = 0; si < NUM_SERVER_SLOTS; si++) {
    if(CCS_UNION_SIG_SHARE[context][si] != NULL) {
      dec_ref_cnt(CCS_UNION_SIG_SHARE[context][si]);
      CCS_UNION_SIG_SHARE[context][si] = NULL;
    }
  }
    

  /* No longer interested in receiving prepare certificates */
  if(context == PENDING_CONTEXT)
    PCRCV_Clear_Pcert_Array();

  for(si = 1; si <= NUM_SITES; si++ ) {
    UTIL_Stopwatch_Start( &(UNION_FORWARD_STOPWATCH[si]));
  }
}

/* 
 * Assumption: Pre-Prepare will always be present (non-null) in a valid
 * prepare certificate 
 */
int32u Is_Pending_Slot_Intermediate(pending_slot_struct *pss)
{
  if(pss->prepare_certificate.pre_prepare)
    return TRUE;
  else
    return FALSE;
}

int32u Is_Global_Slot_Intermediate(global_slot_struct *gss)
{
  if(gss->proposal)
    return TRUE;
  else
    return FALSE;
}
