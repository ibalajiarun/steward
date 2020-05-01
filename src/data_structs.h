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

#ifndef DATA_STRUCTS_AJA2J3WYR2BQ8MGJS
#define DATA_STRUCTS_AJA2J3WYR2BQ8MGJS

#include "util/arch.h"
#include "stdutil/stdhash.h"
#include "openssl_rsa.h"
#include "tc_wrapper.h"
#include "util/sp_events.h"
#include "stopwatch.h"

#define SPINES_PORT 8200
#define STW_PORT    8400

#include "configuration.h"

/* JWL SPEED Windows */

/* Window for local area ordering */
#define LOCAL_WINDOW 2 

/* Window for wide area ordering */
#ifdef SET_USE_SPINES
#define GLOBAL_WINDOW 16 
#else
#define GLOBAL_WINDOW 16 
#endif

/* These values should not be changed by the user */
#define NUM_SERVERS_IN_SITE   (3*NUM_FAULTS+1)
			      /* Number of servers in site static value.
			       */


#define UNIQUE_SPINES_STW_PORT(site,server)  (STW_PORT + (NUM_SERVERS_IN_SITE*site)+ server) 


#define NUM_SERVER_SLOTS       NUM_SERVERS_IN_SITE+1  /* Static maximum number
						       * of server elements */
#define FALSE                  0
#define TRUE                   1

#define SIG_SHARE_SIZE	       SIGNATURE_SIZE
#define SIG_SHARE_PROOF_SIZE   128

#define NET_CLIENT_PROGRAM_TYPE    1
#define NET_SERVER_PROGRAM_TYPE    2

/* Message Types */

#define PREPARE_TYPE                1
#define PRE_PREPARE_TYPE            2
#define SIG_SHARE_TYPE              3
#define PROPOSAL_TYPE               4
#define ACCEPT_TYPE                 5
#define UPDATE_TYPE	            6
#define L_NEW_REP_TYPE	            7
#define CLIENT_RESPONSE_TYPE        8
#define ORDERED_PROOF_TYPE          9
#define LOCAL_RECONCILIATION_TYPE   10

#define QUERY_TYPE                  11
#define CLIENT_QUERY_RESPONSE_TYPE  12

#define SITE_GLOBAL_VIEW_CHANGE_TYPE 14 
#define SITE_LOCAL_VIEW_PROOF_TYPE   15

#define GLOBAL_RECONCILIATION_TYPE  16

#define COMPLETE_ORDERED_PROOF_TYPE 17

#define CCS_INVOCATION_TYPE          50
#define CCS_REPORT_TYPE              51
#define CCS_DESCRIPTION_TYPE         52
#define CCS_UNION_TYPE               53


typedef byte packet_body[MAX_PACKET_SIZE];

/* Message structures:
 *
 * Messages are composed of the following structures.
 */
typedef struct dummy_signed_message {
    byte sig[SIGNATURE_SIZE];
    int32u site_id;    /* site id */
    int32u machine_id; /* server id or client id depending on the type of the message */
    int32u len;        /* length of the content */
    int32u type;       /* type of the message */
    /* Content of message follows */
} signed_message;

/* Update content. Note that an update message has almost the same structure as
 * a signed message. It has an additional content structure that contains the
 * time stamp. Therefore, an update message is actually a signed_message with
 * content of update_content and the actual update data */
typedef struct dummy_update_message {
    int32 address;
    int32u time_stamp;
    /* the update content follows */
} update_message;

typedef struct dummy_query_message {
  int32 address;
  int32u time_stamp;
  /* query content follows */
} query_message;

typedef struct dummy_l_new_rep_message {
    int32u view;
} l_new_rep_message;

typedef struct dummy_global_view_change_message {
    int32u global_view;
} global_view_change_message;

typedef struct dummy_local_view_proof_message {
    int32u local_view;
} local_view_proof_message;


typedef struct dummy_pre_prepare_message { 
    int32u seq_num;          /* seq number */
    int32u local_view;       /* the local view number */
    int32u global_view;      /* the global view number */
    /* the update follows */  
} pre_prepare_message;

/* Structure of a Prepare Message */
typedef struct dummy_prepare_message {
    int32u seq_num;                      /* seq number */
    int32u local_view;                   /* the local view number */
    int32u global_view;                  /* the global view number */
    byte update_digest[DIGEST_SIZE];  /* a digest of the update */
} prepare_message;

/* Structure of a Proposal message. */
typedef struct dummy_proposal_message {
    int32u seq_num;           /* the seq number of the proposal */
    int32u local_view;        /* the local view number */
    int32u global_view;       /* the global view number */
    /* an update_message follows this message */
} proposal_message;

/* Structure of an Accept message. */
typedef struct dummy_accept_message {
    int32u seq_num;           /* seq number */
    int32u global_view;       /* the global view */
    byte update_digest[DIGEST_SIZE]; /* digest of the update */
} accept_message;

typedef struct dummy_ordered_proof_message {
    int32u time_stamp;
    /* A complete proposal message follows */
} ordered_proof_message;

/* Structure of Signature Share Message. The signature share is on the content 
 * which follows the sig_share_proof. A signed message follows this message. */
typedef struct dummy_sig_share_message {
    byte sig_share_proof[SIG_SHARE_PROOF_SIZE];  /* proof that share is valid */
#if 0
    byte sig_share[SIG_SHARE_SIZE];              /* signature share */
    int32u site_id;				 /* the id of the site signing
						    the data */
    int32u len;					 /* The len of the content */ 
    int32u type;				 /* The type of the content */
#endif
    /* A signed message follows -- the signed message does not have a
     * signature, instead it contains the signature share */
} sig_share_message;

/* A Prepare certificate consists of 1 Pre-Prepare and 2f Prepares */
typedef struct dummy_prepare_certificate {
    //byte update_digest[DIGEST_SIZE];    /* The update digest */
    signed_message* pre_prepare;        /* The pre_prepare message */
    signed_message* prepare[NUM_SERVER_SLOTS]; /* The set of prepares */
} prepare_certificate_struct;

/* Reconciliation request */
typedef struct dummy_local_reconciliation_message {
    int32u global_seq_num;
    int32u local_seq_num;
    int32u time_stamp;
} local_reconciliation_message;

/* Global reconciliation request */
typedef struct dummy_global_reconciliation_message {
  int32u seq_num;
} global_reconciliation_message;


/* Local Data Structure Slot. */
typedef struct dummy_pending_slot {
    int32u seq_num;					/* seq number */
    signed_message *pre_prepare;			/* current pre prepare
							 */
    signed_message* prepare[NUM_SERVER_SLOTS];          /* current prepares */
    int32u send_sig_share_on_prepare;			/* Flag to signal if a
							   signature share
							   should be sent when
							   the next prepare is
							   processed by the
							   protocol */
    prepare_certificate_struct prepare_certificate;	/* Last prepare
							   certificate */
    signed_message* sig_share[NUM_SERVER_SLOTS];        /* current sig shares
							   for proposal */
    signed_message *proposal;				/* generated proposal
							 */
    sp_time time_pre_prepare_sent;

    sp_time time_proposal_sent;

    int32u purge_view;

} pending_slot_struct;

/* Global Data Structure Slot */
typedef struct dummy_global_slot {
    signed_message* proposal;                          /* proposal */
    signed_message* accept[NUM_SITES+1];               /* set of accepts */
    signed_message* accept_share[NUM_SERVER_SLOTS];    /* accept share */
    int32u is_ordered;
    sp_time time_accept_share_sent;
    util_stopwatch stopwatch_complete_ordered_proof_site_broadcast;
    util_stopwatch forward_proposal_stopwatch;
    int32u purge_view;
} global_slot_struct;

/* Client response message */
typedef struct dummy_client_response_message {
    int32u seq_num;
    int32u time_stamp;
} client_response_message;

/* Data structures -- the following structs are used to hold the data
 * structures to be used that will be globally available. */

#if 0
/* Startup */
nt32u   My_ID;
int32u   My_Site_ID;
int32u   Faults;

/* Nodes */
Node     All_Nodes[MAX_NODES];

/* Clients */
Client   All_Clients[MAX_CLIENTS];
#endif

typedef struct server_variables_dummy {
    int32u My_Server_ID;
    int32u My_Site_ID;
    int32u Global_seq;
    int32u Faults;
} server_variables;

typedef struct network_variables_dummy {
    int32    My_Address;
    int32    Mcast_Address;
    int16u   Port;
    channel  Send_Channel;
    channel  Spines_Channel;
    int32u   program_type;
} network_variables;

typedef struct dummy_global_data_struct {
    int32u View;
    int32u Installed;
    int32u Max_ordered;
    stdhash History;
    int32u ARU;
    signed_message* Global_VC[NUM_SITES+1];
    signed_message* Global_VC_share[NUM_SERVER_SLOTS];
    int32u Is_preinstalled;
    int32u maximum_pending_view_when_progress_occured;
} global_data_struct;

typedef struct dummy_pending_data_structs {
    int32u View;
    int32u Is_preinstalled;
    int32u Max_ordered;
    int32u ARU;
    stdhash History;
    signed_message *L_new_rep[NUM_SERVER_SLOTS];
    signed_message *Local_view_proof[NUM_SITES+1];
    signed_message *Local_view_proof_share[NUM_SERVER_SLOTS];
} pending_data_struct;

/* Keeping track of clients. */

typedef struct dummy_client_slot_struct {
    int32u pending_time_stamp; /* set this to the client's timestamp when the
				  leader site rep injects update into system */
    int32u globally_ordered_time_stamp; /* set this when a client's response is
					   globally ordered */
    int32u global_seq_num; /* set this to the seq num of the update with the
			      greatest time stamp */
} client_slot_struct;

typedef struct dummy_client_data_struct {
    client_slot_struct client[NUM_SITES+1][NUM_CLIENTS+1];
} client_data_struct;

/* Public Functions */

void DAT_Initialize(); 

#endif
