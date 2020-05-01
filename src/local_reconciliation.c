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

#include "data_structs.h"
#include "utility.h"
#include "error_wrapper.h"
#include "util/arch.h"
#include "util/alarm.h"
#include "util/memory.h"
#include "timeouts.h"
#include "ordered_receiver.h"
#include "global_reconciliation.h"
#include <string.h>

/* Globally Accessible Variables */

extern server_variables VAR;

extern global_data_struct GLOBAL;

extern pending_data_struct PENDING;

/* Local variables */

int32u time_stamp;

int32u slot_position; /* The number of the slot to answer */

/* Local Functions */
signed_message* LRECON_Construct_Reconciliation_Message(int32u global_seq_num,
    int32u local_seq_num ); 
void LRECON_Send_Next( int dummy, void* dummyp ); 
void LRECON_Process_Local_Reconciliation_Message( signed_message *recon ); 
void LRECON_Broadcast_Proposal( int32u seq_num ); 
void LRECON_Broadcast_ARU_Ordered_Proof( int dummp, void* dummyp ); 
void LRECON_Automatic_Reconciliation( int dummp, void* dummyp ); 

typedef struct dummy_local_reconciliation_data_slot {
    sp_time time;
    int32u time_stamp;
    int32u global_seq_num;
    int32u local_seq_num;
} local_reconciliation_data_slot;

util_stopwatch request_stopwatch;

int32u last_global_seq_num_requested;
int32u last_local_seq_num_requested;

local_reconciliation_data_slot lrecon_slot[NUM_SERVER_SLOTS];

void LRECON_Initialize() {

    int32u server;
    
    /* Local reconcilliation initialization */ 
    time_stamp = 0;    

    slot_position = 0;

    for ( server = 1; server <= NUM_SERVERS_IN_SITE; server++ ) {
	lrecon_slot[server].time.sec = 0;
	lrecon_slot[server].time.usec = 0;
	lrecon_slot[server].time_stamp = 0;
	lrecon_slot[server].global_seq_num = 0;
	lrecon_slot[server].local_seq_num = 0;
    }

    UTIL_Stopwatch_Start(&request_stopwatch);
    last_global_seq_num_requested = 0;
    last_local_seq_num_requested = 0;

/* Local reconciliation automatic */    
#if 1 
    E_queue( LRECON_Send_Next, 0, NULL, timeout_local_reconciliation );
    E_queue( LRECON_Broadcast_ARU_Ordered_Proof, 0, NULL,
	    timeout_local_reconciliation_aru_global_proof );
    E_queue( LRECON_Automatic_Reconciliation, 0, NULL,
	    timeout_local_reconciliation_auto_reconciliation );
#endif
 
}

void LRECON_Process_Message( signed_message *mess ) {

    Alarm(DEBUG,"%d %d LRECON_Process_Message from %d %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID,
	    mess->site_id, mess->machine_id);
    
    if ( mess->type == LOCAL_RECONCILIATION_TYPE ) {
	LRECON_Process_Local_Reconciliation_Message( mess ); 
    }
    
}

void LRECON_Do_Reconciliation() {

    /* If the seq num of the greatest proposal that I have received exceeds my
     * LOCAL.ARU, then I need to request a retransmission. */

    signed_message *recon;
    int32u global_seq_num, local_seq_num;

    Alarm(DEBUG,"LRECON_Do_Reconciliation\n");
    
    global_seq_num = 0;
    local_seq_num = 0;
    
    if ( GLOBAL.Max_ordered > GLOBAL.ARU ) {
	global_seq_num = GLOBAL.ARU + 1; /* global seq num to request */
    }
    
    if ( UTIL_I_Am_In_Leader_Site() && 
	 PENDING.Max_ordered > PENDING.ARU ) {
	/* If I am in the leader site, then also ask for a local seq num */
        local_seq_num = PENDING.ARU + 1; /* pending seq num to request */ 
    }
    
    UTIL_Stopwatch_Stop( &request_stopwatch );

    if ( local_seq_num == 0 &&
         global_seq_num == 0  ) {
	/* Nothing needed */
	return;
    }
   
    Alarm(DEBUG,"elapsed: %f\n",UTIL_Stopwatch_Elapsed( &request_stopwatch ));
    
    if ( GLOBAL.Max_ordered < GLOBAL.ARU + LOCAL_WINDOW && 
	 PENDING.Max_ordered < PENDING.ARU + LOCAL_WINDOW &&
	 UTIL_Stopwatch_Elapsed( &request_stopwatch ) < 0.050 ) {
	return;
    }
    
    /* If the time that the last request was less than timeout */
    if ( UTIL_Stopwatch_Elapsed( &request_stopwatch ) < 0.050 && 
        ( last_global_seq_num_requested == global_seq_num && 
	  last_local_seq_num_requested == local_seq_num )) {
	/* wait a while before sending another identical request */
	Alarm(DEBUG,"DON'T SEND\n");
	return;
    } else {
	Alarm(DEBUG,"***** DO SEND\n");
    }
  
    UTIL_Stopwatch_Start( &request_stopwatch );
    last_global_seq_num_requested = global_seq_num;
    last_local_seq_num_requested = local_seq_num;
    
    /* Note: We can also request the sequence number of a proposal if we are in
     * the leader site. */
    
    Alarm(DEBUG,"SENDING local_reconciliation_message for %d %d\n",
	    global_seq_num, local_seq_num );
    recon = LRECON_Construct_Reconciliation_Message(global_seq_num,local_seq_num);
   
    /* Send the message */
    UTIL_Site_Broadcast(recon);

    /* Dispose of the message */
    dec_ref_cnt(recon);
}

signed_message* LRECON_Construct_Reconciliation_Message(int32u global_seq_num,
    int32u local_seq_num ) { 

    /* Construct a reconciliation message. This message contains a timestamp
     * and a sequence number. The timestamp is used to prevent replay attacks.
     * A reconciliation message is ignored unless it has a later time stamp
     * than the last reconciliation message received from the same server. */

    signed_message *recon;
    local_reconciliation_message *recon_specific;

    recon = UTIL_New_Signed_Message();

    recon_specific = (local_reconciliation_message*)(recon+1);
    
    recon->site_id = VAR.My_Site_ID;
    recon->machine_id = VAR.My_Server_ID;
    recon->type = LOCAL_RECONCILIATION_TYPE;
    recon->len = sizeof(local_reconciliation_message);
    time_stamp++;
    recon_specific->time_stamp = time_stamp;
    recon_specific->global_seq_num = global_seq_num;
    recon_specific->local_seq_num = local_seq_num;

    UTIL_RSA_Sign_Message( recon );

    return recon;
    
}

void LRECON_Process_Local_Reconciliation_Message( signed_message *recon ) {

    /* Respond to a local reconciliation message. */

    local_reconciliation_message *recon_specific;
    
    recon_specific = (local_reconciliation_message*)(recon+1);

    /* Sanity check */
    if ( recon->site_id != VAR.My_Site_ID ) {
	Alarm(PRINT,"LRECON_Process_Local_Reconciliation_Message: Not my site.\n");
	return;
    }

    if ( recon->machine_id == VAR.My_Server_ID ) {
	return;
    }
    
    /* To prevent reconciliation performance attacks, responses should be throttled based on time   */

    Alarm(DEBUG,"%d %d recon_message_ts %d %d\n", VAR.My_Site_ID, VAR.My_Server_ID,
	  recon_specific->time_stamp, lrecon_slot[recon->machine_id].time_stamp);
    
    /* If the time_stamp is not greater than last message received from this
     * server, ignore it. */
    if ( recon_specific->time_stamp <= lrecon_slot[recon->machine_id].time_stamp ) {
	return;
	/* Note: Optimization can be used by placing a counter where each
	 * time_stamp is good for some number of requests. */
    }

    Alarm(DEBUG,"%d %d Recon %d %d %d %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, recon_specific->global_seq_num, recon->site_id,
	    recon->machine_id, GLOBAL.ARU );
    
    /* The message can be processed. Set seq_num to retransmit. */
    lrecon_slot[recon->machine_id].global_seq_num = recon_specific->global_seq_num;
    lrecon_slot[recon->machine_id].local_seq_num = recon_specific->local_seq_num;
     
    /* Update the time stamp */
    lrecon_slot[recon->machine_id].time_stamp = recon_specific->time_stamp;
 
}

void LRECON_Send_Next( int dummy, void* dummyp ) {

    /* Send next reconciliation response, if there is one pending. */
    
    int32u slot_count;
    int32u try_to_send_proposal;
    
    slot_position++;
    
    if ( slot_position > NUM_SERVERS_IN_SITE ) {
	slot_position = 1;
    }
    
    slot_count = 0;
    
    Alarm(DEBUG,"LRECON_Send_Next\n");
    
    while ( lrecon_slot[slot_position].global_seq_num == 0 && 
	    lrecon_slot[slot_position].local_seq_num == 0 && 
	    slot_count <= NUM_SERVERS_IN_SITE ) {
	slot_position++;
	slot_count++;
	if ( slot_position > NUM_SERVERS_IN_SITE ) {
	    /* wrap around to next position in slot */
	    slot_position = 1;
	}
    }

    try_to_send_proposal = 1;
    if ( lrecon_slot[slot_position].global_seq_num != 0 ) {
	/* Broadcast the ordered proof... if we have ordered the requested seq num */
	if ( UTIL_Is_Globally_Ordered( lrecon_slot[slot_position].global_seq_num ) ) {
	    Alarm(DEBUG,"%d %d Sending %d\n",
		    lrecon_slot[slot_position].global_seq_num);
	    	GRECON_Send_Response( lrecon_slot[slot_position].global_seq_num,                  0, 0 );
		/*ORDRCV_Send_Ordered_Proof_Bundle( 
		lrecon_slot[slot_position].global_seq_num, 0 , 0 );*/
	    try_to_send_proposal = 0;
	}
    }

    /* Examine the local request -- if I have a proposal for it, then send
     * the proposal */
    if ( try_to_send_proposal &&
	 lrecon_slot[slot_position].local_seq_num != 0 ) {
	if ( UTIL_Is_Pending_Proposal_Ordered( 
			    lrecon_slot[slot_position].local_seq_num ) ) {
	    LRECON_Broadcast_Proposal(lrecon_slot[slot_position].local_seq_num );
	}
    }

    lrecon_slot[slot_position].global_seq_num = 0;
    lrecon_slot[slot_position].local_seq_num = 0;

    E_queue( LRECON_Send_Next, 0, NULL, timeout_local_reconciliation );

}

void LRECON_Broadcast_Proposal( int32u seq_num ) {

    pending_slot_struct *slot;

    slot = UTIL_Get_Pending_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( slot->proposal != NULL ) {
	UTIL_Site_Broadcast( slot->proposal );
    }
    
}

void LRECON_Broadcast_ARU_Ordered_Proof( int dummp, void* dummyp ) {

    if ( GLOBAL.ARU > 0 ) {
	/* Send the ordered proof */
	//ORDRCV_Send_Ordered_Proof_Bundle( GLOBAL.ARU, 0, 0 );
	GRECON_Send_Response( GLOBAL.ARU, 0, 0 );
    }

    if ( PENDING.ARU > 0 ) {
	LRECON_Broadcast_Proposal(PENDING.ARU);
    }

    E_queue( LRECON_Broadcast_ARU_Ordered_Proof, 0, NULL,
	    timeout_local_reconciliation_aru_global_proof );

   
}

void LRECON_Automatic_Reconciliation( int dummp, void* dummyp ) {

    /* Auto reconciliation */
    LRECON_Do_Reconciliation();
    E_queue( LRECON_Automatic_Reconciliation, 0, NULL,
	    timeout_local_reconciliation_auto_reconciliation );

    
} 


