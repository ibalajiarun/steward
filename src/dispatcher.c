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

/* The dispatcher sends messages, based on type, to one of the protocols. All
 * messages are of type signed_message. */

#include "data_structs.h"
#include "dispatcher.h"
#include "assign_sequence.h"
#include "meta_globally_order.h"
#include "threshold_sign.h"
#include "global_view_change.h"
#include "construct_collective_state_protocol.h"
#include "rep_election.h"
#include "ordered_receiver.h"
#include "error_wrapper.h"
#include "local_reconciliation.h"
#include "prepare_certificate_receiver.h"
#include "apply.h"
#include "util/alarm.h"
#include "query_protocol.h"
#include "global_reconciliation.h"

/* Protocol types */
#define PROT_INVALID             0
#define PROT_ASEQ                1 
#define PROT_THRESH                  2
#define PROT_CCS                  3
#define PROT_GVC                  4
#define PROT_META_GLOBALLY_ORDER 5
#define PROT_REP_ELECTION        6
#define PROT_ORDERED_RECEIVER    7
#define PROT_LOCAL_RECON         8
#define QUERY_HANDLER            9
#define META_GLOBAL_VC          10 
#define GLOBAL_RECON            11

/* Dispatch Code */

int32u DIS_Classify_Message( signed_message *mess ) {

    int32u mt;

    mt = mess->type;
   
    if ( mt == UPDATE_TYPE || mt == PRE_PREPARE_TYPE || 
	    mt == PREPARE_TYPE ) {
	return PROT_ASEQ;
    }
   
    if ( mt == SIG_SHARE_TYPE ) {
	return PROT_THRESH;
    } 

    if ( mt == PROPOSAL_TYPE || mt == ACCEPT_TYPE ) {
	return PROT_META_GLOBALLY_ORDER;
    }

    if ( mt == L_NEW_REP_TYPE ||
         mt == SITE_LOCAL_VIEW_PROOF_TYPE ) {
    	return PROT_REP_ELECTION;
    }
   
    if ( mt == ORDERED_PROOF_TYPE ) {
	return PROT_ORDERED_RECEIVER;
    }

    if ( mt == LOCAL_RECONCILIATION_TYPE ) {
	return PROT_LOCAL_RECON;
    }

    if ( mt == CCS_INVOCATION_TYPE || 
	 mt == CCS_REPORT_TYPE || 
	 mt == CCS_DESCRIPTION_TYPE 
	 ) {
	return PROT_CCS;
    }

    if ( mt == CCS_UNION_TYPE ) {
	return META_GLOBAL_VC;
    }

    if( mt == QUERY_TYPE) {
      return QUERY_HANDLER;
    }
   
    if ( mt == SITE_GLOBAL_VIEW_CHANGE_TYPE ) {
	return PROT_GVC;
    }

    if( mt == GLOBAL_RECONCILIATION_TYPE ) {
      return GLOBAL_RECON;
    }

    /* Otherwise, we have received an invalid message type. */
    Alarm(EXIT,"*********** %d\b",mt);
    return 0;
    
}

void DIS_Dispatch_Message( signed_message *mess ) {

    int32u prot_type;

    prot_type = DIS_Classify_Message( mess );

    switch ( prot_type ) {
	case PROT_ASEQ:
	    ASEQ_Dispatcher( mess );
	    return; 
	case PROT_THRESH:
	    THRESH_Process_Threshold_Share( mess ); 
	    return;
	case PROT_REP_ELECTION:
	    Alarm(DEBUG,"Recv l_new_rep\n");
	    REP_Process_Message( mess );
	    REP_Update_Preinstall_Status();
	    return;
	case PROT_META_GLOBALLY_ORDER:
	    if ( mess->type == PROPOSAL_TYPE ) {
		ASEQ_Process_Proposal( mess );
	    }
	    GLOBO_Dispatcher( mess );
	    return;
	case PROT_ORDERED_RECEIVER:
	    ORDRCV_Process_Ordered_Proof_Message( mess );
	    return;
	case PROT_LOCAL_RECON:
	    LRECON_Process_Message( mess );
	    return;
	case PROT_CCS:
	    CCS_Dispatcher( mess );   
	    return;
        case QUERY_HANDLER:
	    Query_Handler( mess );
	    return;
	case PROT_GVC:
	    GVC_Process_Message( mess );
	    return;  
	case META_GLOBAL_VC:
	    CCS_Process_Union_Message( mess );
	    return;
        case GLOBAL_RECON:
	  GRECON_Dispatcher( mess );
	  return;

	default:
	    INVALID_MESSAGE(""); 
    }

}

void DIS_Dispatch_Message_Pre_Conflict_Checking( 
	signed_message *mess ) {

    if ( mess->type == PRE_PREPARE_TYPE ||
	 mess->type == PREPARE_TYPE ||
         mess->type == PROPOSAL_TYPE ) {
	/* Send to the prepare certificate receiver -- this code receives
	 * prepare certificates consisting of possibly many pre-prepare and
	 * prepare messages for old views. */
	PCRCV_Process_Message( mess );
    }

    if ( mess->type == ACCEPT_TYPE ) {
	ORDRCV_Process_Accept(mess);
    }

    if ( mess->type == PROPOSAL_TYPE ) {
	APPLY_Proposal( mess );
    }

}
