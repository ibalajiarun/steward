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
#include "meta_globally_order.h"
#include "validate.h"
#include <string.h>

/* Globally Accessible Variables */

extern server_variables VAR;

extern global_data_struct GLOBAL;

/* Local Functions */
signed_message *Construct_Global_Reconciliation_Message(int32u seq);
void GRECON_Send_Response( int32u seq_num, int32u site, int32u server ); 
void GRECON_Send_Request(); 
void GRECON_Init();
void GRECON_Retrans( int32 dummy, void *dummyp ); 
void GRECON_Send_Request_If_I_Am_In_Leader_Site( signed_message *recon ); 
void GRECON_Send_Request_If_I_Am_In_Non_Leader_Site( signed_message *recon );

util_stopwatch send_stopwatch;

/* Local Variables */
int32u IS_STARTED;
int32u target_global_seq;

void GRECON_Start_Reconciliation( int32u target ) {

    if ( target > target_global_seq ) {
	target_global_seq = target;
    }

    Alarm(GRECON_PRINT,"Start global reconciliation. target: %d g.aru %d\n", 
	    target, GLOBAL.ARU );

    if ( IS_STARTED ) {
	return;
    }

    IS_STARTED = 1;

    /* Send */
    E_queue( GRECON_Retrans, 0, NULL, timeout_zero );

}

void GRECON_Send_Response( int32u seq_num, int32u site, int32u server ) {

    signed_message *p;

    p = GRECON_Construct_Ordered_Proof_Message( seq_num );

    if ( p == NULL ) {
	return;
    }
   
    if ( site == 0 || server == 0 ) {
	UTIL_Site_Broadcast( p );
	return;
    }

    UTIL_Send_To_Server(p, site, server);

    /*ORDRCV_Send_Ordered_Proof_Bundle( seq_num, 
            site, server );*/ 

    /* We could throttle here to defend against DoS attacks. */

}

void GRECON_Send_Request() {

    signed_message *recon;

    if ( !IS_STARTED || GLOBAL.ARU >= target_global_seq ) {
	return;
    }

    recon = Construct_Global_Reconciliation_Message( GLOBAL.ARU + 1 );

    /* Send it to f+1 servers at the leader site INCLUDING the representative
     * */

    if ( UTIL_I_Am_In_Leader_Site() ) {
	GRECON_Send_Request_If_I_Am_In_Leader_Site( recon );
    } else {
	GRECON_Send_Request_If_I_Am_In_Non_Leader_Site( recon );
    }

    dec_ref_cnt(recon);
	
}

void GRECON_Send_Request_If_I_Am_In_Leader_Site( signed_message *recon ) {

    int32u site;
    int32u server;

    /* We want to ask two servers in each of the other sites. */

    if ( UTIL_I_Am_Representative() ) {
	for ( site = 1; site <= NUM_SITES; site++ ) {
	    /* Send to num faults + 1 servers in this site */
	    for ( server = 1; server <= NUM_FAULTS + 1; server++ ) {
		Alarm(GRECON_PRINT,
		    "Leader Requesting RECON from site %d server"
		    " %d for seq %d\n",
		    site, server, GLOBAL.ARU + 1 );
		UTIL_Send_To_Server( recon, site, server );
	    }
	} 
    }
}

void GRECON_Send_Request_If_I_Am_In_Non_Leader_Site( signed_message *recon ) {

    int32u send_count;
    int32u si;
    int32u leader_rep;
    int32u leader_site;

    leader_site = UTIL_Leader_Site();

    leader_rep = UTIL_Get_Site_Representative(leader_site);    

    Alarm(GRECON_PRINT,"SENDING RECON\n");

    UTIL_Send_To_Server( recon, leader_site, leader_rep );

    send_count = 0;
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	if ( si != leader_rep ) {
	    /* Send to this server */
	    Alarm(GRECON_PRINT,"Non Leader Requesting RECON from site %d server"
		" %d for seq %d\n",
		leader_site, si, GLOBAL.ARU + 1 );
	}	
	UTIL_Send_To_Server( recon, leader_site, si );
	send_count++;
	if ( send_count == NUM_FAULTS ) {
	    si = NUM_SERVERS_IN_SITE + 1;
	}
    }

}

void GRECON_Dispatcher( signed_message *mess ) {

    if ( mess->type == GLOBAL_RECONCILIATION_TYPE ) {
	GRECON_Send_Response( 
	     ((global_reconciliation_message*)(mess+1))->seq_num
		, mess->site_id, mess->machine_id );
    }

}

void GRECON_Init() {

    IS_STARTED = 0;

    target_global_seq = 0;

    UTIL_Stopwatch_Start( &send_stopwatch );

    //if ( VAR.My_Site_ID == 3 )
    //	GRECON_Start_Reconciliation(400);

}

void GRECON_Retrans( int32 dummy, void *dummyp ) {

    /* Reached target */
    if ( GLOBAL.ARU >= target_global_seq ) {
	IS_STARTED = 0;
	return;
    }

    GRECON_Send_Request();

    E_queue( GRECON_Retrans, 0, NULL, timeout_global_reconciliation );

}

signed_message *Construct_Global_Reconciliation_Message(int32u seq)
{
  signed_message *grecon;
  global_reconciliation_message *grecon_specific;

  grecon = UTIL_New_Signed_Message();
  grecon_specific = (global_reconciliation_message *)(grecon + 1);

  grecon->site_id    = VAR.My_Site_ID;
  grecon->machine_id = VAR.My_Server_ID;
  grecon->type       = GLOBAL_RECONCILIATION_TYPE;
  grecon->len        = sizeof(global_reconciliation_message);

  grecon_specific->seq_num = seq;

  UTIL_RSA_Sign_Message(grecon);

  return grecon;
}

signed_message* GRECON_Construct_Ordered_Proof_Message( int32u seq_num ) {

    /* Make a SPECIAL message */

    global_slot_struct *slot;
    proposal_message *proposal_specific;
    accept_message *accept_specific;
    signed_message *proof;
    signed_message *update;
    update_message *update_specific;
    int32u gview, si, accept_count, accept_len;
    signed_message *the_accepts[NUM_SITES+1];
    signed_message *current;

    slot = UTIL_Get_Global_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return NULL;
    }

    if ( !slot->is_ordered ) {
	/* We have not ordered this message SO we cannot build the proof */
	return NULL;
    }

    /* Let's build the proof */
    proof = UTIL_New_Signed_Message();

    /* The view must be the same as the proposal */
    if ( slot->proposal == NULL ) {
      Alarm(GRECON_PRINT,"GRECON_Construct_Ordered_Proof -- NULL proposal\n");
      dec_ref_cnt(proof);
      return NULL;
    }

    proposal_specific = (proposal_message*)(slot->proposal+1);
    gview             = proposal_specific->global_view;

    accept_count = 0;
    for(si = 0; si <= NUM_SITES; si++)
      the_accepts[si] = NULL;

    /* Iterate through the list of accepts in this slot, and try to find
     * NUM_SITES/2 of them with the same global view as the proposal.  */
    for(si = 1; si <= NUM_SITES; si++) {
      if(slot->accept[si] != NULL) {
	accept_specific = (accept_message *)(slot->accept[si]+1);
	if(accept_specific->global_view == proposal_specific->global_view) {
	  the_accepts[si] = slot->accept[si];
	  accept_count++;
	  
	  if(accept_count == (NUM_SITES / 2) )
	    break;
	}
      }
    }

    /* If we don't have enough accepts from the same view to construct an 
     * ordered proof, give up. */
    if(accept_count != (NUM_SITES / 2)) {
      Alarm(GRECON_PRINT, "GRECON_Construct_Ordered_Proof -- NULL proposal\n");
      dec_ref_cnt(proof);
      return NULL;
    }
    
    /* We've found the right number of accepts.  Now copy them into the
     * message buffer.  We know there must be NUM_SITES/2 of them. */
    current = proof;
    accept_len = sizeof(signed_message) + sizeof(accept_message);

    for(si = 1; si <= NUM_SITES; si++) {
      if(the_accepts[si] != NULL) {
	memcpy(current, the_accepts[si], accept_len);
	current = (signed_message*)
	    (((byte*)(current + 1)) + sizeof(accept_message));
	//current = (signed_message *)((byte *)(current + accept_len));
      }
    }

    Alarm(DEBUG,"%d \n",slot->proposal->len);

    /* At this point, current is in position to copy the proposal */
    memcpy(current, slot->proposal, 
	   sizeof(signed_message) + slot->proposal->len);

    /* Set the type and len only on the first accept in the bunch */
    proof->type = COMPLETE_ORDERED_PROOF_TYPE;
    proof->len  = ( (sizeof(accept_message) * (NUM_SITES/2)) + 
		    (sizeof(signed_message) * (NUM_SITES/2 - 1)) + 
		    sizeof(signed_message) + slot->proposal->len );
    
    /* Check which timestamp we're responding for */
    update = (signed_message *)(proposal_specific+1);
    update_specific = (update_message *)(update+1);
    Alarm(GRECON_PRINT, "Constructed proof for client timestamp %d\n", 
	  update_specific->time_stamp);

    return proof;
    
#if 0

    /* THIS WORKS ONLY FOR THREE SITES */

    /* Find an accept that matches the view */
    the_accept = NULL;
    for ( si = 1; si <= NUM_SITES; si++ ) {
	if ( slot->accept[si] != NULL ) {
	    accept_specific = (accept_message*)(slot->accept[si]+1); 
	    if ( accept_specific->global_view == 
		    proposal_specific->global_view ) {
		the_accept = slot->accept[si];
		si = NUM_SITES+1;
	    }
	}
    }

    if ( the_accept == NULL ) {
	Alarm(GRECON_PRINT,"GRECON_Construct_Ordered_Proof -- NULL proposal\n");
	return NULL;
    }

    /* Copy the accept into the first part of the message */
    memcpy( (void*)(proof), 
	    (void*)the_accept,
	    sizeof(signed_message) + the_accept->len );

    /* Copy the proposal */
    memcpy( (void*)( ((byte*)(proof+1)) + sizeof(accept_message)),
	    (void*)(slot->proposal),
	    sizeof(signed_message) + slot->proposal->len );
	    	
    /* Set the type */
    proof->type = COMPLETE_ORDERED_PROOF_TYPE;

    /* Set the new size */
    proof->len = sizeof(accept_message) +
                 sizeof(signed_message) +
		 slot->proposal->len;

    return proof;
#endif
}

/* Returns 1 if this was a Complete_Ordered_Proof message, 0 otherwise. 
 * If it is the right type, validate the Accept and Proposal portions.  If
 * both validate, and some other tests pass, apply it to my data structures
 * ...*/
int32u GRECON_Process_Complete_Ordered_Proof(signed_message *mess, 
					     int32u num_bytes, 
					     signed_message **ret_prop, 
					     int32u caller_is_client)
{
  signed_message *current_accept;
  signed_message *new_accepts[NUM_SITES + 1]; /* Extra space just to be sure*/
  signed_message *new_proposal, *old_proposal;
  accept_message   *accept_specific;
  proposal_message *proposal_specific;
  int32u accept_len, proposal_len;
  global_slot_struct *g_slot;
  int32u site_ids[NUM_SITES+1];
  int32u seq, global_view;
  int32u i, j;
  int32u non_proposal_len;


  if(mess->type != COMPLETE_ORDERED_PROOF_TYPE) {
    *ret_prop = NULL;
    return 0;
  }

  /* Initialize, for safety */
  for(i = 0; i <= NUM_SITES; i++) {
    new_accepts[i] = NULL;
    site_ids[i] = 0;
  }

  Alarm(GRECON_PRINT,"GOT COMPLETE ORDERED PROOF\n");

  /* The received message consists of NUM_SITES/2 accept messages followed 
   * by a Proposal.  The type is COMPLETE_ORDERED_PROOF_TYPE and the
   * length */

  accept_len = sizeof(signed_message) + sizeof(accept_message);

  /* mess->len is set to: 
     ( (sizeof(accept_message) * (NUM_SITES/2)) + 
     (sizeof(signed_message) * (NUM_SITES/2 - 1)) + 
     sizeof(signed_message) + slot->proposal->len );
  */
  
  non_proposal_len =  ( (sizeof(accept_message) * (NUM_SITES/2)) + 
			(sizeof(signed_message) * (NUM_SITES/2 - 1)) );

  /* Make sure the length is at least the size of the constant stuff  */
  if(num_bytes < non_proposal_len) {
    *ret_prop = NULL;
    return 1;
  }

  /* The message length should be at least this much */
  if(mess->len <= non_proposal_len + sizeof(signed_message) +
     sizeof(proposal_message) ) {
    *ret_prop = NULL;
    Alarm(DEBUG,"WRONG LENGTH: complete ordered proof\n");
    return 1;
  }

  /* The proposal is the message length minus everything that's not a prop */
  proposal_len = mess->len - non_proposal_len;

  if( (proposal_len < sizeof(signed_message) + sizeof(proposal_message)) ||
      proposal_len > 1024 ) {
    *ret_prop = NULL;
    return 1;
  }  

  /* Iterate through NUM_SITES/2 Accept messages starting from the
   * beginning of the message.  Copy each one into a new buffer.  Then
   * copy the proposal (the last part of the message) into a buffer of
   * its own.*/

  /* Copy each of the accept messages */
  current_accept = mess;
  for(i = 0; i < NUM_SITES / 2; i++) {
    new_accepts[i] = UTIL_New_Signed_Message();
    memcpy(new_accepts[i], current_accept, accept_len);
    accept_specific = (accept_message *)(current_accept + 1);
    current_accept  = (signed_message *)(accept_specific + 1);
  }

  /* At this point, current_accept points to the signed message that
   * is the beginning of the proposal.  Now just copy the Proposal
   * (last part of mess) into a new buffer */
  old_proposal      = current_accept;
  new_proposal      = UTIL_New_Signed_Message();
  memcpy(new_proposal, old_proposal, proposal_len);

  /* Validate the Accept messages.  For each, make sure its type and 
   * length is for an Accept message.  Then validate away.  If any fails,
   * bail out and free up all the memory we've allocated. */
  for(i = 0; i < NUM_SITES / 2; i++) {
    new_accepts[i]->type = ACCEPT_TYPE;
    new_accepts[i]->len  = sizeof(accept_message);

    if( !VAL_Validate_Message(new_accepts[i], accept_len) ) {
      for(j = 0; j < NUM_SITES / 2; j++) {
	dec_ref_cnt(new_accepts[j]);
      }
      dec_ref_cnt(new_proposal);
      *ret_prop = NULL;
      return 1;
    }
  }
   
  /* Validate the proposal.  If it fails, free up all the memory we've
   * allocated.  */
  if( !VAL_Validate_Message(new_proposal, proposal_len) ) {
    for(i = 0; i < NUM_SITES / 2; i++) {
      dec_ref_cnt(new_accepts[i]); 
    }
    dec_ref_cnt(new_proposal);
    *ret_prop = NULL;
    return 1;        
  }

  /* The global view numbers on all of these things should be the same. 
   * First grab the proposal global view, and then compare it to all
   * accept views.  If all match, happiness.*/
  proposal_specific = (proposal_message *)(new_proposal+1);  
  global_view       = proposal_specific->global_view;
  for(i = 0; i < NUM_SITES / 2; i++) {
    accept_specific = (accept_message *)(new_accepts[i]+1);
    
    if(accept_specific->global_view != global_view) {
      for(j = 0; j < NUM_SITES / 2; j++) {
	dec_ref_cnt(new_accepts[j]);
      }
      dec_ref_cnt(new_proposal);
      *ret_prop = NULL;
      return 1;
    }
  }

  /* Make sure the sequence numbers on all the things match.*/
  seq = proposal_specific->seq_num;
  for(i = 0; i < NUM_SITES / 2; i++) {
    accept_specific = (accept_message *)(new_accepts[i]+1);

    if(accept_specific->seq_num != seq) {
      for(j = 0; j < NUM_SITES / 2; j++) {
	dec_ref_cnt(new_accepts[j]);
      }
      dec_ref_cnt(new_proposal);
      *ret_prop = NULL;
      return 1;
    }
  }  
  
  /* Make sure all site ID's of the Accept messages do not conflict*/
  for(i = 0; i < NUM_SITES / 2; i++) {
    /* If we've already seen this site id, bail out */
    if(site_ids[new_accepts[i]->site_id] == 1) {
      for(j = 0; j < NUM_SITES / 2; j++) {
	dec_ref_cnt(new_accepts[j]);
      }
      dec_ref_cnt(new_proposal);
      *ret_prop = NULL;
      return 1;
    }
    site_ids[new_accepts[i]->site_id] = 1;
  }
  
  *ret_prop = new_proposal;

  if(caller_is_client)
    return 1;
  
  /* If we get here, all ID's are different */
  g_slot = UTIL_Get_Global_Slot(seq);
  
  /* If the slot is ordered, no need to do anything */
  if(g_slot->is_ordered) {
    for(i = 0; i < NUM_SITES / 2; i++) {
      dec_ref_cnt(new_accepts[i]);
    }
    dec_ref_cnt(new_proposal);  
    return 1;
  }

  /* Clear out the proposal if one exists */
  if(g_slot->proposal != NULL) {
    dec_ref_cnt(g_slot->proposal);
    g_slot->proposal = NULL;
  }
  
  /* Clear out any accepts that exist */
  for(i = 0; i <= NUM_SITES; i++) {
    if(g_slot->accept[i] != NULL) {
      dec_ref_cnt(g_slot->accept[i]);
      g_slot->accept[i] = NULL;
    }
  }

  /* Clear out any accept shares that exist */
  for(i = 0; i < NUM_SERVER_SLOTS; i++) {
    if(g_slot->accept_share[i] != NULL) {
      dec_ref_cnt(g_slot->accept_share[i]);
      g_slot->accept_share[i] = NULL;
    }
  }

  /* Put the complete ordered proof into the data structure */
  g_slot->proposal = new_proposal;

  for(i = 0; i < NUM_SITES / 2; i++) {
    g_slot->accept[new_accepts[i]->site_id] = new_accepts[i];
  }

  Alarm(GRECON_PRINT,"GOT COMPLETE VALID ORDERED PROOF\n");

  /* The slot is now ordered! */
  GLOBO_Handle_Global_Ordering(g_slot);

  if( UTIL_I_Am_Representative() ) {
    UTIL_Stopwatch_Stop( 
	&g_slot->stopwatch_complete_ordered_proof_site_broadcast );
    if ( UTIL_Stopwatch_Elapsed(
	&g_slot->stopwatch_complete_ordered_proof_site_broadcast ) >
	    0.020 ) {
	UTIL_Stopwatch_Start( 
	    &g_slot->stopwatch_complete_ordered_proof_site_broadcast );
	UTIL_Site_Broadcast( mess );
    }
  }

  return 1;
}
