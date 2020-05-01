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
  File:  construct_collective_state_protocol.h
  Date:  October 15, 2005
  Usage: Defines structures and messages for CCS
--------------------------------------------------*/

#ifndef CCS_PROTOCOL_H
#define CCS_PROTOCOL_H

#include "data_structs.h"

/* 
 * Type of entry in Report or Union.  Intermediate refers to
 * Prepare_Certificate (pending) or Proposal (global), and Ordered
 * refers to Proposal (pending) or globally ordered message (global).
 * context.
 */
#define INTERMEDIATE_TYPE  57
#define ORDERED_TYPE       58

#define PENDING_CONTEXT     0  
#define GLOBAL_CONTEXT      1

#define NUM_CONTEXTS 2

enum ccs_states {INITIAL_STATE, INVOCATION_RECEIVED, REPORT_SENT, 
		COLLECTING_REPORT_CONTENTS,
		COLLECTING_UNION_CONTENTS, COLLECTING_SIG_SHARES};

typedef struct dummy_ccs_state_struct {
  int32u Invocation_ARU[NUM_CONTEXTS];
  int32u Latest_Invocation_View[NUM_CONTEXTS];
  int32u State[NUM_CONTEXTS];
  int32u My_Max_Seq_Response[NUM_CONTEXTS];
} ccs_state_struct;

/* 
 * NOTE: We may need 3 context types: PENDING, GLOBAL_LEADER, GLOBAL_NON_LEADER
 */
typedef struct dummy_ccs_invocation_message {
  int32u local_view;     /* The view number */
  int32u global_view;
  int32u context;  /* Context in which ccs invoked: PENDING or GLOBAL */
  int32u aru;      /* Aru of representative or leader site           */
} ccs_invocation_message;

typedef struct dummy_ccs_report_message {
  int32u context;  /* Context in which reported data exist: PENDING or GLOBAL*/
  int32u local_view;
  int32u global_view;
  int32u aru;      /* ARU of the reporting server in the given context       */
  int32u num_entries;  /* Number of entries in the report list */
  /* Report_List follows...*/
} ccs_report_message;

typedef struct dummy_pending_report_entry {
  int32u type;              /* INTERMEDIATE or ORDERED                  */
  int32u seq;               /* Sequence number associated with entry    */ 
  int32u local_view;        /* Local View number associated with entry  */
  int32u global_view;       /* Global view number associated with entry */
  byte digest[DIGEST_SIZE]; /* Only useful for prepare certificates     */
} ccs_pending_report_entry;

typedef struct dummy_global_report_entry {
  int32u type;        /* INTERMEDIATE or ORDERED               */
  int32u seq;         /* Sequence number associated with entry */
  int32u local_view;  /* Local view number: IGNORED            */
  int32u global_view; /* Global  view number of the entry      */
} ccs_global_report_entry;


/*
 * Each server maintains the Collected_Reports temporary data
 * structure to store CCS_Report messages as they come in.
 *
 * The representative takes action when he collects 2f+1 CCS_Report
 * messages, and has the contents of each of these messages.  He sends
 * a CCS_Description message, which includes the identifiers of those
 * CCS_Report messages that should be considered in the upcoming Union.
 *
 * The non-representatives collect CCS_Report messages as well, but
 * only after receiving the representative's description message.
 * action.
 */

typedef struct dummy_ccs_digest_struct {
  byte digest[DIGEST_SIZE];
} ccs_digest_struct;

typedef struct dummy_ccs_collected_reports_struct {
  signed_message *Report_List[NUM_CONTEXTS][NUM_SERVERS_IN_SITE+1];
  int32u num_reports_collected[NUM_CONTEXTS];
  int32u num_completed_reports[NUM_CONTEXTS];
  int32u completed_report_list[NUM_CONTEXTS][NUM_SERVERS_IN_SITE+1];
  
  signed_message *Description[NUM_CONTEXTS];
  int32u report_in_description[NUM_CONTEXTS][NUM_SERVERS_IN_SITE+1];
  ccs_digest_struct report_digests[NUM_CONTEXTS][NUM_SERVERS_IN_SITE+1];
} ccs_collected_reports_struct;

typedef struct dummy_ccs_description_message {
  int32u context;
  int32u local_view;
  int32u global_view;
  int32u num_entries;
  /* Report_Description_List follows...*/
} ccs_description_message;

typedef struct dummy_description_entry {
  int32u machine_id; /* 0 if not set, non-zero otherwise */
  byte   digest[DIGEST_SIZE];
} description_entry;

typedef struct dummy_ccs_union_message {
  int32u context;
  int32u local_view;
  int32u global_view;
  int32u aru;  /* ARU of the site */
  /* Description of what appears in the union follows...*/
} ccs_union_message;

typedef struct dummy_ccs_union_struct {
  stdhash union_data[NUM_CONTEXTS];
  int32u num_entries_remaining[NUM_CONTEXTS];
} ccs_union_struct;


/* Stored in the hash, allocated dynamically per sequence number */
typedef struct dummy_union_entry {
  int32u type; /* INTERMEDIATE or ORDERED */
  int32u local_view;
  int32u global_view;
  byte digest[DIGEST_SIZE]; /* Set if context = PENDING and type = INTERMED.*/
  
  int32u marked; /* If this entry is fulfilled */
} ccs_union_entry;

/* Global Functions */
void CCS_Dispatcher                 (signed_message *m);
void CCS_Send_Invocation_Message    ( int32u context, int32u aru ); 

/* 
 * Callback function: Called when the aru is increased or when an invocation
 * message is received.  
 */
void CCS_Response_Decider(int32u context);

/* 
 * Callback function: Used by the representative, and called when he has
 * finished collecting the contents of 2f+1 report entries.
 */
void CCS_Report_Decider(int32u context);

/* 
 * Callback function: Called when the aru is increased and whenever something
 * that may be in the union is received. 
 */
void CCS_Union_Decider(int32u context);

int32u CCS_Am_I_Constrained_In_Pending_Context();

void CCS_Handle_Union_Message( signed_message *new_ccs_union );

void CCS_Process_Union_Message( signed_message *ccs_union );

int32u CCS_Is_Globally_Constrained();

void CCS_Global_Response_Decider();

#endif 
