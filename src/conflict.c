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

/* The conflict code (conflict.h and conflict.c) verifies whether the 
 * content of an incoming message is in conflict with existing data
 * structures.
 */ 

#include "conflict.h"
#include "data_structs.h"
#include "utility.h"
#include "string.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "error_wrapper.h"


/* Gobally Accessible Variables */

extern server_variables VAR;
extern global_data_struct GLOBAL;
extern pending_data_struct PENDING;


/* Local Functions */

int32u CONFL_Check_Pre_Prepare( signed_message *message, int32u num_bytes );

int32u CONFL_Check_Prepare( signed_message *message, int32u num_bytes );

int32u CONFL_Check_Sig_Share( signed_message *message, int32u num_bytes );

int32u CONFL_Check_Proposal( signed_message *message, int32u num_bytes );

int32u CONFL_Check_Accept( signed_message *message, int32u num_bytes );



/* Determine whether a pre-prepare has a conflict */
int32u CONFL_Check_Pre_Prepare( signed_message *message, int32u num_bytes )
{
    pending_slot_struct *p_slot;
    pre_prepare_message *new_pre_prepare_specific;
    pre_prepare_message *old_pre_prepare_specific;
    signed_message *old_pre_prepare;
    signed_message *proposal;
    proposal_message *proposal_specific;
    int i;

    new_pre_prepare_specific = (pre_prepare_message*)(message + 1);

    Alarm(CONFLICT_PRINT,"CONFL_Check_Pre_prepare seq = %d, lv = %d, p.view = %d\n",
	  new_pre_prepare_specific->seq_num, 
	  new_pre_prepare_specific->local_view, 
	  PENDING.View);

    /* I should be at the leader site */
    if( !UTIL_I_Am_In_Leader_Site() ) {
      Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: I'm not in leader site.\n");
      return TRUE;
    }
  
    if( message->machine_id != UTIL_Representative() ) {
      Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: Not from representative.\n");
      return TRUE;
    }
    
    if( (new_pre_prepare_specific->local_view  != PENDING.View)||
	(new_pre_prepare_specific->global_view != GLOBAL.View) ) {
      Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: Differnt views %d %d\n", 
	    new_pre_prepare_specific->local_view, 
	    PENDING.View);
      return TRUE;
    }

    p_slot = UTIL_Get_Pending_Slot_If_Exists(
					   new_pre_prepare_specific->seq_num );

    /* No previous slot, can't have a pre_prepare, no problem */
    if(p_slot == NULL)
      return FALSE;

    /* If the new pre_prepare's local view is higher than the existing
     * one, then we replace the existing one with the new one, and
     * clear all of the prepares from the temporary area.*/
    if ( p_slot->pre_prepare != NULL ) { 
	old_pre_prepare = p_slot->pre_prepare;
	old_pre_prepare_specific = (pre_prepare_message*)(old_pre_prepare + 1);

	if( (new_pre_prepare_specific->local_view > 
	     old_pre_prepare_specific->local_view) ) {
	  /* THIS CODE ONLY WORKS IF YOU CLEAR OUT THE PENDING DATA STRUCTURE
	   * WHEN YOU TRANSITION TO A NEW GLOBAL VIEW.*/

	  Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: Clearing out temporary\n");
	  dec_ref_cnt(p_slot->pre_prepare);
	  p_slot->pre_prepare = NULL;
	  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
	    if( p_slot->prepare[i] != NULL ) {
	      dec_ref_cnt(p_slot->prepare[i]);
	      p_slot->prepare[i] = NULL;
	    }
	  }
	}

	if( (new_pre_prepare_specific->local_view ==                   
             old_pre_prepare_specific->local_view) ) {
	  /* If the existing pre_prepare is current, then the one I'm
	   * considering had better be the same length and have the same
	   * content. */
	  if(num_bytes-sizeof(signed_message) != old_pre_prepare->len) {
	    return TRUE;
	  }
	  if( memcmp(message, old_pre_prepare, num_bytes) != 0 ) {
	    return TRUE; 
	  }	
	}
    }

    /* Check against a previous prepare-certificate.  If there is a
     * prepare certificate, then the pre_prepare therein must have the
     * same length and update as the one I'm considering. */
    if( p_slot->prepare_certificate.pre_prepare != NULL ) {
      old_pre_prepare = p_slot->prepare_certificate.pre_prepare;
      old_pre_prepare_specific = (pre_prepare_message *)(old_pre_prepare+1);

      if( new_pre_prepare_specific->local_view <= 
	  old_pre_prepare_specific->local_view ) {
	if( old_pre_prepare->len != message->len ) {
	  Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: Wrong mess lenn");
	  return TRUE;
	}
	old_pre_prepare_specific = (pre_prepare_message*)(old_pre_prepare + 1);
	if( memcmp((new_pre_prepare_specific+1), (old_pre_prepare_specific+1), 
		   message->len - sizeof(pre_prepare_message)) != 0 ) {
	  Alarm(CONFLICT_PRINT, "Check_Pre_Prepare: Bad update comparison\n");
	  return TRUE; 
	}
      }
    }

    /* Check against a previous local-ordered update (proposal) */
    if(p_slot->proposal != NULL) {
      proposal = p_slot->proposal;
      proposal_specific = (proposal_message*)(proposal+1);
      if( proposal->len - sizeof(proposal_message) != 
	  message->len - sizeof(pre_prepare_message) ) {
	return TRUE;
      }
      if( memcmp((new_pre_prepare_specific+1), (proposal_specific+1), 
		 message->len - sizeof(pre_prepare_message)) != 0 ) {
	return TRUE; 
      }
    }
 
    return FALSE;
}


int32u CONFL_Check_Prepare( signed_message *message, int32u num_bytes ) 
{
    pending_slot_struct *p_slot;
    prepare_message *prepare_specific;
    pre_prepare_message *pre_prepare_specific;
    signed_message *pre_prepare;
    byte update_digest[DIGEST_SIZE];

    prepare_specific = (prepare_message*)(message + 1);

    Alarm(CONFLICT_PRINT,"CONFL_Check_Prepare %d lv = %d\n", prepare_specific->seq_num, 
	  prepare_specific->local_view);

    /* If I don't have a pre_prepare for the same global and local view
     * in this slot already, throw this prepare out. */
    p_slot = UTIL_Get_Pending_Slot_If_Exists( prepare_specific->seq_num );

    /* Have nothing (don't have pre_prepare) so conflict */
    if(p_slot == NULL)
      return TRUE;

    pre_prepare          = p_slot->pre_prepare;
    pre_prepare_specific = (pre_prepare_message*)(pre_prepare + 1);
    
    if(pre_prepare == NULL)
      return TRUE;

    if( (prepare_specific->local_view  != PENDING.View)||
	(prepare_specific->global_view != GLOBAL.View) ) {
      Alarm(CONFLICT_PRINT, "Check_Prepare: Bad views\n");
      return TRUE;
    }	
    
    /* There is a pre_prepare in the slot.  It must have the same global
     * and local view as the prepare I just got. */
    if( pre_prepare_specific->local_view != prepare_specific->local_view ||
	pre_prepare_specific->global_view != prepare_specific->global_view )
      return TRUE;
	
    OPENSSL_RSA_Make_Digest( ((byte*)(pre_prepare_specific + 1)), 
			     pre_prepare->len - sizeof(pre_prepare_message),
			     update_digest );
    
    if (!OPENSSL_RSA_Digests_Equal(update_digest, 
				   prepare_specific->update_digest))
      return TRUE;

    /* There is a pre_prepare in this slot with the same local, global view, 
     * and the update digest from the pre_prepare matches the one included 
     * in the prepare I just received. */

    /* If I already have a proposal in this slot, the proposal that I
     * have for this local view is fixed.*/
    if(p_slot->proposal != NULL) 
      return TRUE;

    return FALSE;
}

int32u CONFL_Check_Sig_Share( signed_message *message, int32u num_bytes ) 
{
    sig_share_message *sig_share;
    signed_message *signed_msg;
    signed_message *proposal;
    proposal_message *proposal_specific;

    sig_share  = (sig_share_message*)(message + 1);
    signed_msg = (signed_message*)(sig_share + 1);
    
    if(signed_msg->type != PROPOSAL_TYPE)
      return FALSE;

    proposal = signed_msg;
    proposal_specific = (proposal_message*)(proposal + 1);
    
    if( (proposal_specific->local_view  != PENDING.View) ||
	(proposal_specific->global_view != GLOBAL.View) ) {
      Alarm(CONFLICT_PRINT, "Conf_sig: lv = %d, gv = %d, p.view = %d, g.view = %d\n",
	    proposal_specific->local_view, 
	    proposal_specific->global_view,
	    PENDING.View,
	    GLOBAL.View);
      return TRUE;
    }

    return FALSE;

#if 0	
    /* Check against a previous pre-prepare */
    p_slot = UTIL_Get_Pending_Slot_If_Exists( proposal_specific->seq_num );

    /* No Pre-Prepare, can't be a conflict */
    if(p_slot == NULL)
      return FALSE;
	
    if ( p_slot->pre_prepare != NULL ) { 
      pre_prepare = p_slot->pre_prepare;
      pre_prepare_specific = (pre_prepare_message*)(pre_prepare + 1);

      if((pre_prepare_specific->local_view  != PENDING.View) ||
	 (pre_prepare_specific->global_view != GLOBAL.View)) {
	/* There is an old pre_prepare message in the pending data
	 * structure.  It is impossible to have a pre_prepare newer
	 * than current view */
	if(p_slot->prepare_certificate.pre_prepare == NULL) {
	  dec_ref_cnt(p_slot->pre_prepare);
	  p_slot->pre_prepare = NULL;
	  for(i=1; i<=NUM_SERVERS_IN_SITE; i++) {
	    if(p_slot->prepare[i] != NULL) {
	      dec_ref_cnt(p_slot->prepare[i]);
	      p_slot->prepare[i] = NULL;
	    }
	  }
	}
      }
      else {
	if( local_pre_prepare_msg->len - sizeof(pre_prepare_message) != 
	    proposal_msg->len - sizeof(proposal_message) ) {
	  return TRUE;
	}
	if( memcmp((proposal+1), (local_pre_prepare+1), 
		   proposal_msg->len - sizeof(proposal_message)) != 0 ) {
	  return TRUE; 
	}			
      }
    }
    
	
    /* Check against a previous local-ordered update (proposal) */
    if(p_slot->proposal != NULL) {
      local_proposal_msg = p_slot->proposal;
      local_proposal = (proposal_message*)(local_proposal_msg+1);
      
      if( local_proposal_msg->len != proposal_msg->len ) {
	return TRUE;
      }
      if( memcmp((proposal+1), (local_proposal+1), 
		 proposal_msg->len - sizeof(proposal_message)) != 0 ) {
	return TRUE; 
      }			
    }
#endif
}


int32u CONFL_Check_Proposal( signed_message *message, int32u num_bytes ) 
{
    global_slot_struct *g_slot;
    signed_message *local_proposal_msg;
    proposal_message *proposal, *local_proposal;

    proposal = (proposal_message*)(message+1);

#if 0    
    if( proposal->global_view != GLOBAL.View ) {
	return TRUE;
    }	
#endif

    g_slot = UTIL_Get_Global_Slot_If_Exists( proposal->seq_num );
    
    /* If I have no old proposal, then no conflict */
    if(g_slot == NULL)
      return FALSE;

    if ( g_slot->is_ordered ) { 
	local_proposal_msg = g_slot->proposal;
	local_proposal = (proposal_message*)(local_proposal_msg+1);
	if(message->len != local_proposal_msg->len) {
	    return TRUE;
	}
	if( memcmp((proposal+1), (local_proposal+1), 
		   local_proposal_msg->len - sizeof(proposal_message)) != 0 ) {
	    return TRUE; 
	}		
    }
	
    return FALSE;
}



int32u CONFL_Check_Accept( signed_message *message, int32u num_bytes ) 
{
    global_slot_struct *g_slot;
    accept_message *accept;

    accept = (accept_message*)(message+1);

    /* Only process Accepts from my global view */
    if( accept->global_view != GLOBAL.View ) {
      Alarm(CONFLICT_PRINT, "incoming gv = %d, my gv = %d, accept seq %d\n", 
	    accept->global_view, GLOBAL.View, accept->seq_num);
      return TRUE;
    }
    
    g_slot = UTIL_Get_Global_Slot_If_Exists( accept->seq_num );
 
    return FALSE;
}




/* Global Functions */

/* Determine if a message from the network is conflicting the existing
 * data structures. */
int32u CONFL_Check_Message( signed_message *message, int32u num_bytes )
{
    
    switch (message->type) {
    case PRE_PREPARE_TYPE:
	return CONFL_Check_Pre_Prepare( message, num_bytes );
	
    case PREPARE_TYPE:
	return CONFL_Check_Prepare( message, num_bytes );
	
    case SIG_SHARE_TYPE:
	return CONFL_Check_Sig_Share( message, num_bytes );
	
    case PROPOSAL_TYPE:
	return CONFL_Check_Proposal( message, num_bytes );
	
    case ACCEPT_TYPE:
	return CONFL_Check_Accept( message, num_bytes );
	    
    case UPDATE_TYPE:
	return FALSE;
	
    default:
	return FALSE;

    }
    return TRUE;
}
