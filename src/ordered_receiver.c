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
#include "meta_globally_order.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "stdutil/stddll.h"
#include "apply.h"
#include <string.h>

/* These files receive ordered messages from any server in the system. */

retrans_struct ordered_proof_retrans;

extern server_variables VAR;

typedef struct dummy_ordered_proof_struct {
    signed_message *ordered_proof;
    signed_message *accept[NUM_SITES+1];
} ordered_proof_struct;

int32u time_stamp;
ordered_proof_struct ordered_proof[NUM_SITES+1][NUM_SERVER_SLOTS];

/* Local Functions */
void ORDRCV_Check_Proof( ordered_proof_struct *op ); 
ordered_proof_struct* ORDRCV_Get_Ordered_Proof_Struct( int32u site, int32u server ); 
int32u ORDRCV_Add_Accept( ordered_proof_struct *op, signed_message *accept ); 
int32u ORDRCV_Add_Ordered_Proof( ordered_proof_struct *op, signed_message *op_mess ); 


void ORDRCV_Initialize() {

    /* Initialize the ordered proof data structure */
    
    int32u site, server, accept_index;

    for ( site = 0; site <= NUM_SITES; site++) {
	for ( server = 0; server < NUM_SERVER_SLOTS; server++ ) {
	    ordered_proof[site][server].ordered_proof = NULL;
	    for ( accept_index = 0; accept_index <= NUM_SITES; accept_index++) {
		ordered_proof[site][server].accept[accept_index] = NULL;
	    }
	}
    }

    /* Set the time stamp to 0 */
    time_stamp = 0;
 
    /* Initialize message retransmission */
    ordered_proof_retrans.repeat = 0;

    ordered_proof_retrans.inter_message_time.usec = 5000;
    ordered_proof_retrans.inter_message_time.sec = 0;

    ordered_proof_retrans.inter_group_time.usec = 0;
    ordered_proof_retrans.inter_group_time.usec = 0;

    UTIL_RETRANS_Construct(&ordered_proof_retrans);

}

ordered_proof_struct* ORDRCV_Get_Ordered_Proof_Struct( int32u site, int32u server ) {

    /* Retrieve a pointer to an ordered proof structure based on the site and
     * server id */
    
    ordered_proof_struct *ret;

    ret = NULL;

    if ( site < 1 || site > NUM_SITES ) {
	return ret;
    }
   
    if ( server < 1 || server > NUM_SERVERS_IN_SITE ) {
	return ret;
    }

    return &ordered_proof[site][server];    
 
}

int32u ORDRCV_Add_Accept( ordered_proof_struct *op, signed_message *accept ) {

    /* Add the specified accept message if it matches the proposal */

    proposal_message *proposal_specific;
    accept_message *accept_specific;

    Alarm(DEBUG,"%d %d ORDRCV_Add_Accept %d\n",VAR.My_Site_ID,
	    VAR.My_Server_ID,op->ordered_proof);
 
    if ( op->ordered_proof == NULL ) {
	/* There is no proposal, so an accept cannot be added */
	return 0;
    }
    
    proposal_specific = (proposal_message*)
	( (byte*)(op->ordered_proof) + sizeof(signed_message) 
	  + sizeof(ordered_proof_message) + sizeof(signed_message) );
   
    accept_specific = (accept_message*)(accept+1);

    Alarm(DEBUG,"%d %d ORDRCV_Add_Accept gv: %d %d seq: %d %d\n",VAR.My_Site_ID,
	    VAR.My_Server_ID, proposal_specific->global_view,
	    accept_specific->global_view, proposal_specific->seq_num,
	    accept_specific->seq_num);
 
    if ( accept_specific->global_view == proposal_specific->global_view
	 && accept_specific->seq_num == proposal_specific->seq_num   
       ) {
	/* The accept is for the SAME view number and seq number as the stored
	 * proposal */
	/* Store the accept */
	if ( op->accept[accept->site_id] != NULL ) {
	    /* An accept was already stored here, so decrement its reference
	     * counter */
	    dec_ref_cnt(op->accept[accept->site_id]);
	}
	inc_ref_cnt(accept);
	op->accept[accept->site_id] = accept;
	/* The accept message was added -- return 1 so that a check can be run
	 * to determine if there is proof that the message was ordered. */
	return 1;
    }

    /* The accept message was not added */
    return 0;
}

int32u ORDRCV_Add_Ordered_Proof( ordered_proof_struct *op, signed_message *op_mess ) {

    /* Add an ordered proof message if the message has a timestamp that is
     * greater than the timestamp of the current ordered proof (or there is no
     * ordered proof) */

    ordered_proof_message *old_op, *new_op;
    
    if ( op->ordered_proof == NULL ) {
	/* Nothing is here, so add it */
	inc_ref_cnt( op_mess );
	op->ordered_proof = op_mess;
	return 1;
    }

    old_op = (ordered_proof_message*)(op->ordered_proof+1);
    new_op = (ordered_proof_message*)(op_mess+1);

    if ( new_op->time_stamp > old_op->time_stamp ) {
	/* The new time stamp is greater than the old one -- the new
	 * ordered_proof message can replace the old one */
	dec_ref_cnt(op->ordered_proof);
	inc_ref_cnt(op_mess);
	op->ordered_proof = op_mess;
	return 1;
    }

    return 0;
    
}

void ORDRCV_Process_Ordered_Proof_Message( signed_message *op_mess ) {

    /* Assume that the ordered proof message has been validated. */

    ordered_proof_struct *op;
    proposal_message *proposal_specific;
    global_slot_struct *slot;
    
    Alarm(DEBUG,"%d %d ORDRCV_Process_Ordered_Proof_Message\n", VAR.My_Site_ID,
	    VAR.My_Server_ID );

    /* Get the global slot for the sequence number of the proposal in the
     * oredered proof. If this slot is already ordered, don't process this
     * ordered proof message. */
   
    proposal_specific = (proposal_message*)
	(((byte*)(op_mess)) + sizeof(signed_message) + 
	 sizeof(ordered_proof_message)
	 + sizeof(signed_message));

    Alarm(DEBUG,"%d %d ORDRCV_Process_Ordered_Proof_Message seq: %d\n", VAR.My_Site_ID,
	    VAR.My_Server_ID, proposal_specific->seq_num );

    slot = UTIL_Get_Global_Slot_If_Exists( proposal_specific->seq_num );

    if ( slot != NULL ) {
	if ( slot->is_ordered ) {
	    /* We already ordered this slot */
	    Alarm(DEBUG,"ALREADY ORDERED\n");
	    return;
	}
    }
    
    op = ORDRCV_Get_Ordered_Proof_Struct( op_mess->site_id, op_mess->machine_id);
    
    if ( ORDRCV_Add_Ordered_Proof(op,op_mess) ) {
	Alarm(DEBUG,"%d %d"
		" ORDRCV_Process_Ordered_Proof_Message -- added ordered proof\n",
		VAR.My_Site_ID, VAR.My_Server_ID );
	/* Could check to see if a proof exists */
    }

}

void ORDRCV_Process_Accept( signed_message *accept ) {

    /* Assume that the ordered proof message has been validated. */

    ordered_proof_struct *op;
    int32u site, server;
    accept_message *accept_specific;
    global_slot_struct *slot;

    Alarm(DEBUG,"%d %d ORDRCV_Process_Accept\n", VAR.My_Site_ID,
	    VAR.My_Server_ID, accept->site_id, accept->machine_id );
   
    accept_specific = (accept_message*)(accept+1);
    
    slot = UTIL_Get_Global_Slot_If_Exists( accept_specific->seq_num );

    if ( slot != NULL ) {
	if ( slot->is_ordered ) {
	    /* We already ordered this slot */
	    return;
	}
    }
     /* For each ordered proof struct (one for each server in the system), add
     * accept message */
    
    for ( site = 1; site <= NUM_SITES; site++) {
	for ( server = 1; server <= NUM_SERVERS_IN_SITE; server++ ) {
	    op = ORDRCV_Get_Ordered_Proof_Struct(site,
		    server);
	    if ( op != NULL ) {
		if ( ORDRCV_Add_Accept( op, accept  ) ) {
		    /* The accept message was added, check if the op is proof of
		     * global ordereing, and if so, copy it to the global history.
		     * */
		    ORDRCV_Check_Proof( op );
		}
	    }
	}
    }
   
}

void ORDRCV_Check_Proof( ordered_proof_struct *op ) {

    /* Count the number of accepts that match the proposal in the ordered
     * proof. If the number is a majority, then the struct constitutes proof of
     * global ordering AND the proof is copied to the global data structure. */

    int32u site;
    int32u seq;
    int32u global_view;
    proposal_message *proposal_specific;
    int32u accept_count;
    accept_message *accept_specific;
    signed_message *new_proposal;
    signed_message *proposal;
    global_slot_struct *slot;
    
    if ( op->ordered_proof == NULL  ) {
	/* No proof */
	return;
    }

    proposal = (signed_message*)
	((byte*)(op->ordered_proof + 1) + sizeof(ordered_proof_message)); 
 
    proposal_specific = (proposal_message*)
	(proposal + 1); 

    /* The accepts must match the proposal seq_num and global view */
    seq = proposal_specific->seq_num;
    global_view = proposal_specific->global_view;
    
    accept_count = 0;
    for (site = 1; site <= NUM_SITES; site++) {
	if ( op->accept[site] != NULL ) {
	    accept_specific = (accept_message*)
		(op->accept[site] + 1);
	    Alarm(DEBUG,"Found Accept %d %d %d %d\n",global_view,
		    accept_specific->global_view, seq, accept_specific->seq_num );
	    if ( accept_specific->seq_num == seq &&
		    accept_specific->global_view == global_view ) {
		/* The accept matches */
		accept_count++;
	    }
	}
    }

    Alarm(DEBUG,"%d %d accepts: %d majority: %d\n",
	    VAR.My_Site_ID,VAR.My_Server_ID,accept_count,
	    ((int32u)NUM_SITES) / ((int32u)2) );
    
    /* Majority? */
    if ( accept_count + 1 <= ((int32u)NUM_SITES) / 2 ) {
	return;
    }

    /* There was proof, so now copy the proposal and enough accepts */
    
    slot = UTIL_Get_Global_Slot( seq );

    if ( slot->is_ordered ) return;
    
    /* Make a new message to hold the proposal */
    new_proposal = UTIL_New_Signed_Message();

    /* Copy the proposal that is in the ordered proof message to the new proposal */
    memcpy((void*)new_proposal,(void*)proposal,proposal->len + sizeof(signed_message));
   
    //slot->proposal = new_proposal;
    APPLY_Proposal( new_proposal );

    /* Now move the necessary accepts into the slot */
    
    for (site = 1; site <= NUM_SITES; site++) {
	if ( op->accept[site] != NULL ) {
	    accept_specific = (accept_message*)
		(op->accept[site] + 1);
	    if ( accept_specific->seq_num == seq &&
		    accept_specific->global_view == global_view ) {
		/* The accept matches */
		slot->accept[site] = op->accept[site];
	    }
	}
    }

    /* We now need to update the global aru -- this can be done by simply
     * calling the function to handle global ordering on a slot  */
  
    GLOBO_Handle_Global_Ordering(slot);

    //LRECON_Do_Reconciliation();
    /* The ARU has been updated */
 
}

signed_message* ORDRCV_Construct_Ordered_Proof_Message( signed_message *proposal ) {

    /* Construct a new signed message having the form and type of an
     * ordered_proof_message. This is a signed_message with a rsa signature
     * from this server, a timestamp, and a threshold signed proposal message
     * that follows it. */

    signed_message *ordered_proof;
    ordered_proof_message *ordered_proof_specific;

    ordered_proof = UTIL_New_Signed_Message();

    ordered_proof_specific = (ordered_proof_message*)(ordered_proof+1);

    ordered_proof->site_id = VAR.My_Site_ID;
    ordered_proof->machine_id = VAR.My_Server_ID;

    ordered_proof->type = ORDERED_PROOF_TYPE;
    
    time_stamp++;
    ordered_proof_specific->time_stamp = time_stamp; 

    ordered_proof->len = proposal->len + sizeof(signed_message) +
	sizeof(ordered_proof_message);

    /* Copy the proposal into the ordered proof packet */
    memcpy( (void*)(ordered_proof_specific + 1), (void*)proposal,
	    ordered_proof->len + (sizeof(signed_message)));

    /* Sign the message */ 

    UTIL_RSA_Sign_Message( ordered_proof );

    return ordered_proof;

} 

void ORDRCV_Send_Ordered_Proof_Bundle( int32u seq_num, 
       int32u site_id, int32u server_id	) {

    /* Broadcast a bundle */

    global_slot_struct *slot;
    int32u site;
    signed_message *ordered_proof;
 
    /* We should queue the request, but return if we are not yet done sending
     * -- there should be a single pending request for each server in the
     * system and the servers should be given equal turns. */

    /* Temporary -- return if already sending */
    //if ( ordered_proof_retrans.is_started ) {
//	return;
  //  }

    Alarm(DEBUG,"ORDRCV_Send_Ordered_Proof_Bundle\n");

    UTIL_RETRANS_Clear( &ordered_proof_retrans );

    /* Get the global slot */
    slot = UTIL_Get_Global_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( !(slot->is_ordered) ) {
	Alarm(DEBUG,"NOT ORDERED\n");
	return;
    }

    if ( (slot->proposal) != NULL ) {
	ordered_proof = ORDRCV_Construct_Ordered_Proof_Message( slot->proposal ); 
	//UTIL_RETRANS_Add_Message( &ordered_proof_retrans, ordered_proof );
	if ( site_id == 0 || server_id == 0 ) {
	    UTIL_Site_Broadcast( ordered_proof );
	} else {
	    UTIL_Send_To_Server( ordered_proof, site_id, server_id );
	}
	Alarm(DEBUG,"P");
    } else {
	return;
    }

    for ( site = 1; site <= NUM_SITES; site++ ) {
       	if ( slot->accept[site] != NULL ) {
	    //UTIL_RETRANS_Add_Message( &ordered_proof_retrans, slot->accept[site] );
	    if ( site_id == 0 || server_id == 0 ) {
		UTIL_Site_Broadcast( slot->accept[site] );
	    } else {
		UTIL_Send_To_Server( slot->accept[site], 
			site_id, server_id );
	    }
	    Alarm(DEBUG,"A");
	}
    }

    Alarm(DEBUG,"\n");
    
    //UTIL_RETRANS_Start( &ordered_proof_retrans );

}


