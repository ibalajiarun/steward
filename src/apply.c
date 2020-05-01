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

/* Apply messages to the data structures. These functions take a message that
 * has been validated and applies it to the data structures. */

#include "error_wrapper.h"
#include "data_structs.h"
#include "utility.h"
#include "assign_sequence.h"
#include "threshold_sign.h"
#include "rep_election.h"
#include "meta_globally_order.h"
#include "apply.h"
#include "construct_collective_state_protocol.h"
#include "global_view_change.h"
#include "util/memory.h"
#include "util/alarm.h"

/* Gobally Accessible Variables */

extern server_variables VAR;

extern global_data_struct GLOBAL;

extern pending_data_struct PENDING;

extern signed_message *CCS_UNION_SIG_SHARE[2][NUM_SERVER_SLOTS]; /* storage for
								   sig share
								   messages */

extern signed_message *CCS_UNION_MESSAGE[2]; /* storage of actual union messages
					       -- these have valid threshold
					       signatures
					     */


/* Local functions */
void APPLY_Pre_Prepare( signed_message *pre_prepare ); 
void APPLY_Prepare( signed_message *prepare ); 
void APPLY_Sig_Share( signed_message *sig_share );
void APPLY_Accept( signed_message *accept );
void APPLY_Update( signed_message *update );
void APPLY_L_New_Rep( signed_message *update );
void APPLY_Global_View_Change( signed_message *new_gvc );
void APPLY_Local_View_Proof( signed_message *lv_proof ); 

void APPLY_Sig_Share_Proposal( signed_message *sig_share);
void APPLY_Sig_Share_Accept( signed_message *sig_share);
void APPLY_Sig_Share_CCS_Union( signed_message *sig_share);
void APPLY_Sig_Share_Global_View_Change(signed_message* sig_share); 
void APPLY_Sig_Share_Local_View_Proof( signed_message *new_sig_share); 

/* Predicates */
int32u APPLY_Pending_Order_Ready( pending_slot_struct* slot );
int32u APPLY_Accept_Ready( global_slot_struct* slot ); 
int32u APPLY_Global_Order_Ready( global_slot_struct *slot ); 
int32u CCS_Union_Message_Ready( int32u context ); 
int32u APPLY_Global_View_Change_Message_Ready();
int32u APPLY_Local_View_Proof_Message_Ready(); 

/* Generate functions 
 */
signed_message* APPLY_Generate_Proposal( pending_slot_struct *slot); 
signed_message* APPLY_Generate_Accept( global_slot_struct *slot); 
signed_message* APPLY_Generate_CCS_Union( int32u context ); 
signed_message* APPLY_Generate_Global_View_Change();
signed_message* APPLY_Generate_Local_View_Proof(); 

/* Apply a signed message to the data structures. */
void APPLY_Message_To_Data_Structs( signed_message *mess ) {

    switch ( mess->type ) {   
	case PREPARE_TYPE:
	   APPLY_Prepare(mess);
	   return;
	case PRE_PREPARE_TYPE:
	   APPLY_Pre_Prepare(mess);
	   return;
	case SIG_SHARE_TYPE:
	   APPLY_Sig_Share(mess);
	   return;
	case PROPOSAL_TYPE:
	   APPLY_Proposal(mess);
	   return;
	case ACCEPT_TYPE:
	   APPLY_Accept(mess);
	   return;
	case UPDATE_TYPE:
	   APPLY_Update(mess);
	   return;
	case L_NEW_REP_TYPE:
	   APPLY_L_New_Rep(mess);
    	   return;
	case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	   APPLY_Global_View_Change(mess);
	   return;
	case SITE_LOCAL_VIEW_PROOF_TYPE:
	   APPLY_Local_View_Proof(mess);
	   return;
    }

}

void APPLY_Pre_Prepare( signed_message *pre_prepare ) {
    
    pre_prepare_message *pre_prepare_specific;
    pending_slot_struct *slot;
    
    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);

    /* Make sure seq num is not too high. */
    if ( pre_prepare_specific->seq_num > PENDING.ARU + 100 ) {
	return;
    }

    /* Get the slot */
    slot = UTIL_Get_Pending_Slot( pre_prepare_specific->seq_num );

    if ( slot->proposal != NULL ) {
	return;
    }
 
    if ( slot->pre_prepare == NULL ) { 
	inc_ref_cnt(pre_prepare);
	slot->pre_prepare = pre_prepare;
    } else {
	/* TABLE */
    }
 
}

void APPLY_Prepare( signed_message *prepare ) {
    
    prepare_message *prepare_specific;
    pending_slot_struct *slot;
    int32u ti;

    prepare_specific = (prepare_message*)(prepare+1);

    /* Make sure seq num is not too high. */
    if ( prepare_specific->seq_num > PENDING.ARU + 100 ) {
	return;
    }

    /* Get the slot */
    slot = UTIL_Get_Pending_Slot_If_Exists( prepare_specific->seq_num );

    if ( slot == NULL ) {
	return;
    }
  
    if ( slot->proposal != NULL ) {
	return;
    }

    Alarm(DEBUG,"APPLY_PREPARE %d\n",prepare);

    if ( slot->prepare[prepare->machine_id] == NULL ) {
	inc_ref_cnt(prepare);
	Alarm(DEBUG,"PREPARE %d %d \n", prepare, get_ref_cnt(prepare) );
	slot->prepare[prepare->machine_id] = prepare;
	if ( APPLY_Prepare_Certificate_Ready(slot->pre_prepare, slot->prepare, 1 )
		) {
	    for ( ti = 1; ti <= NUM_SERVERS_IN_SITE; ti++ ) {
		if ( slot->prepare[ti] != NULL ) {
		    Alarm(DEBUG,"Mem: %d %d %d\n", ti, slot->prepare[ti],
			get_ref_cnt(slot->prepare[ti])
		         );
		}
	    }
	    APPLY_Move_Prepare_Certificate( &(slot->pre_prepare), 
		    slot->prepare, slot );
	    for ( ti = 1; ti <= NUM_SERVERS_IN_SITE; ti++ ) {
		Alarm(DEBUG,"Mem: %d %d\n",ti,slot->prepare[ti]);
	    }
 	}
    } else {
	/* TABLE */
    }
 
}

void APPLY_Sig_Share( signed_message *sig_share ) {
    /* Depending on the type of message that the sig share is signing, the
     * share will be stored in different places. */
    
    signed_message *content;

    content = (signed_message*)(((sig_share_message*)(sig_share+1))+1);

   
    switch ( content->type ) {
	case PROPOSAL_TYPE:
	    APPLY_Sig_Share_Proposal(sig_share);
	    return;
	case ACCEPT_TYPE:
	    APPLY_Sig_Share_Accept(sig_share);
	    return;
	case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	    APPLY_Sig_Share_Global_View_Change(sig_share);
	    return;
	case SITE_LOCAL_VIEW_PROOF_TYPE:
	    APPLY_Sig_Share_Local_View_Proof(sig_share);
	    return;
	case CCS_UNION_TYPE:
	    APPLY_Sig_Share_CCS_Union(sig_share);
	    return;
    }
 
}

void APPLY_Sig_Share_Proposal( signed_message *sig_share) {

    proposal_message *proposal_specific;
    proposal_message *old_proposal_specific;
    pending_slot_struct *slot;
    signed_message *proposal;
    signed_message *generated_proposal;
    int32u store_it;

    Alarm(DEBUG,"APPLY_Sig_Share_Proposal\n");
    
    proposal = APPLY_Get_Content_Message_From_Sig_Share(sig_share); 
    proposal_specific = (proposal_message*)(proposal+1);

    /* We can store this share in the appropriate pending slot */
   
    /* Get the slot */
    slot = UTIL_Get_Pending_Slot_If_Exists( proposal_specific->seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( slot->proposal != NULL ) {
	return;
    }

    store_it = 0;
    if ( slot->sig_share[sig_share->machine_id] == NULL ) {
	/* Store it */
	store_it = 1;
    } else {
	/* There is a sig share already there, so I need to check the view of
	 * the proposal to see if it should be replaced. */
	old_proposal_specific = (proposal_message*)
	    ( APPLY_Get_Content_Message_From_Sig_Share(
	    slot->sig_share[sig_share->machine_id] )+1);

	if ( old_proposal_specific->local_view < 
	     proposal_specific->local_view ) { 
	    /* The new share should be stored */
	    store_it = 1;
	}
    }

    if ( store_it ) {
	if ( slot->sig_share[sig_share->machine_id] != NULL ) {
	    dec_ref_cnt( slot->sig_share[sig_share->machine_id] );
	}
	slot->sig_share[sig_share->machine_id] = sig_share;
        inc_ref_cnt(sig_share);
 	if ( APPLY_Pending_Order_Ready( slot ) ) {
	    /* combine the signature shares and create a new proposal message.
	     * */
	    generated_proposal = APPLY_Generate_Proposal(slot);
	    if ( generated_proposal != NULL ) {

		/* apply the proposal */
		APPLY_Proposal( generated_proposal );
		Alarm(DEBUG,"Generated proposal\n");
		/* handle the proposal from within CCS */
		ASEQ_Handle_Proposal( generated_proposal );
	    } 
	}
    }

}

void APPLY_Sig_Share_Accept( signed_message *sig_share) {

    sig_share_message *share_specific;
    signed_message *accept;
    accept_message *accept_specific;
    global_slot_struct *slot;

    Alarm(DEBUG,"APPLY_Sig_Share_Accept\n");

    share_specific = (sig_share_message*)(sig_share+1);
    accept = (signed_message*)(share_specific+1);
    accept_specific = (accept_message*)(accept+1);

    /* Make sure seq num is not too high. */
    if ( accept_specific->seq_num > GLOBAL.ARU + 100 ) {
	return;
    }

    /* Get the slot */
    slot = UTIL_Get_Global_Slot( accept_specific->seq_num );

    Alarm(DEBUG,"%d %d mid %d seq %d\n", 
	    VAR.My_Site_ID, VAR.My_Server_ID, sig_share->machine_id, 
	    accept_specific->seq_num);
   
    if ( slot->is_ordered ) {
	return;
    }

    if ( slot->accept_share[sig_share->machine_id] == NULL ) {
        /* Store the share */
	slot->accept_share[sig_share->machine_id] = sig_share;
	inc_ref_cnt(sig_share);
 	if ( slot->accept[VAR.My_Site_ID] == NULL && 
		APPLY_Accept_Ready( slot ) ) {
	    /* combine the signature shares and create a new accept message. */
	    accept = APPLY_Generate_Accept(slot);
	    if ( accept != NULL ) {
		
		/* apply the accept */
		APPLY_Accept( accept );
		Alarm(DEBUG,"Generated accept\n");
		/* handle the accept from within the meta protocol */
		GLOBO_Handle_Accept( accept );
	    }
	}
    } else {
	/* TABLE */
    }
 
    if ( APPLY_Global_Order_Ready( slot ) ) {
	
	Alarm(DEBUG,"%d %d Globally ordered: sn %d\n", 
		VAR.My_Site_ID, VAR.My_Server_ID, accept_specific->seq_num );
	GLOBO_Handle_Global_Ordering( slot );
    }
 
}

signed_message* APPLY_Get_Content_Message_From_Sig_Share( signed_message
	*sig_share ) {

    signed_message *content;
    sig_share_message *sig_share_specific;

    if ( sig_share == NULL ) return NULL;

    sig_share_specific = (sig_share_message*)(sig_share+1);
    content = (signed_message*)(sig_share_specific+1);

    return content;

}

void APPLY_Sig_Share_Local_View_Proof( signed_message *new_sig_share) {
 
    signed_message *new_local_proof;
    signed_message *old_local_proof; 
    signed_message *old_sig_share;
    signed_message *constructed_lv_proof;

    /* Get the old local proof */
    old_sig_share = PENDING.Local_view_proof_share[ new_sig_share->machine_id ];

    old_local_proof = 
        APPLY_Get_Content_Message_From_Sig_Share( old_sig_share );
 
    new_local_proof = 
	APPLY_Get_Content_Message_From_Sig_Share( new_sig_share );
 
    if ( REP_Get_View_From_Proof(new_local_proof) > 
	    REP_Get_View_From_Proof(old_local_proof) ) {
	/* Replace the old one with the new one */
	if ( old_sig_share != NULL ) {
	    dec_ref_cnt( old_sig_share );
	}
	inc_ref_cnt( new_sig_share );
	PENDING.Local_view_proof_share[ new_sig_share->machine_id ] =
	    new_sig_share;
	/* Check to see if there are enough shares to compute signature share.
	 * */
 	if ( APPLY_Local_View_Proof_Message_Ready() ) {
	    constructed_lv_proof = 
		APPLY_Generate_Local_View_Proof();
	    if ( constructed_lv_proof != NULL ) {
		/* Store the message in the slot for my site. */
		PENDING.Local_view_proof[ VAR.My_Site_ID ] = 
		    constructed_lv_proof;
		/* Call a function in rep_election to handle the newly
		 * generated message. */
		REP_Handle_Local_View_Proof_Message( 
			constructed_lv_proof );
	    }
	}

    }
 

}

void APPLY_Sig_Share_Global_View_Change(signed_message* sig_share) {

    signed_message *new_global_vc;
    signed_message *old_global_vc;
    signed_message *old_sig_share;

    signed_message *new_global_view_change; /* the generated threshold signed
					       message */

    old_sig_share = GLOBAL.Global_VC_share[sig_share->machine_id];

    new_global_vc = APPLY_Get_Content_Message_From_Sig_Share( sig_share );
    old_global_vc = APPLY_Get_Content_Message_From_Sig_Share( old_sig_share ); 

    /* Store the sig share if it is for a greater view than the current view.
     * */
    if ( GVC_Get_View(new_global_vc) > GVC_Get_View(old_global_vc) ) {
	if ( old_sig_share != NULL ) {
	    dec_ref_cnt( old_sig_share );
	}
	/* Store the share. */
	inc_ref_cnt(sig_share);
	GLOBAL.Global_VC_share[sig_share->machine_id] = sig_share;
	/* Now check to see if we have enough sig shares to compute the
	 * signature for a new message */
	Alarm(DEBUG,"Checking if global view change message is ready.\n");
 	if ( APPLY_Global_View_Change_Message_Ready() ) {
	    new_global_view_change = 
		APPLY_Generate_Global_View_Change();
	    if ( new_global_view_change != NULL ) {
		/* Store the message in the slot for my site. */
		APPLY_Global_View_Change(new_global_view_change);
		/* Call a function in global_view_change to handle the newly generated
		 * message. */
		GVC_Handle_Global_View_Change_Message( 
			new_global_view_change );
	    }
	}

    }

}

int32u APPLY_Global_View_Change_Message_Ready() {

    int32u si;
    int32u count;
    signed_message *share;
    signed_message *my_share;
    int32u my_global_view;

    count = 0;

    Alarm(DEBUG,"APPLY_Global_View_Change_Message_Ready()\n");

    /* What does my own share say? */
    my_share = GLOBAL.Global_VC_share[VAR.My_Server_ID];
    if ( my_share == NULL ) return 0;

    /* Get the global view of my own sig share */
    my_global_view = GVC_Get_View( 
	    APPLY_Get_Content_Message_From_Sig_Share( my_share ) );

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	share = GLOBAL.Global_VC_share[si];
	if ( share != NULL )  {
	    /* If the share is for the same view as the one that I think is
	     * correct, count it. */
	    if ( my_global_view == GVC_Get_View( 
			APPLY_Get_Content_Message_From_Sig_Share(share) ) ) {
		count++;
	    }
	    Alarm(DEBUG,"%d %d My: %d It's: %d\n",
		    VAR.My_Site_ID, VAR.My_Server_ID, my_global_view,
		GVC_Get_View( APPLY_Get_Content_Message_From_Sig_Share(share) ) );
	}
    }

    if ( count >= 2*VAR.Faults+1 ) {
	/* There are a majority of shares for sig shares equal to mine. */
	return 1;
    }

    /* There aren't enough shares to attempt to combine. */
    return 0;

}

int32u APPLY_Local_View_Proof_Message_Ready() {
    
    int32u si;
    int32u count;
    signed_message *share;
    signed_message *my_share;
    int32u my_local_view;

    count = 0;

    Alarm(DEBUG,"APPLY_Local_View_Proof_Message_Ready()\n");

    /* What does my own share say? */
    my_share = PENDING.Local_view_proof_share[VAR.My_Server_ID];
    if ( my_share == NULL ) return 0;

    /* Get the global view of my own sig share */
    my_local_view = REP_Get_View_From_Proof( 
	    APPLY_Get_Content_Message_From_Sig_Share( my_share ) );

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	share = PENDING.Local_view_proof_share[si];
	if ( share != NULL ) {
	    /* If the share is for the same view as the one that I think is
	     * correct, count it. */
	    if ( my_local_view == REP_Get_View_From_Proof( 
			APPLY_Get_Content_Message_From_Sig_Share(share) ) ) {
		count++;
	    }
	    Alarm(DEBUG,"%d %d My: %d It's: %d\n",
		  VAR.My_Site_ID, VAR.My_Server_ID, my_local_view,
	REP_Get_View_From_Proof( APPLY_Get_Content_Message_From_Sig_Share(share) ) );
	}
    }

    if ( count >= 2*VAR.Faults+1 ) {
	/* There are a majority of shares for sig shares equal to mine. */
	return 1;
    }

    /* There aren't enough shares to attempt to combine. */
    return 0;

} 

void APPLY_Sig_Share_CCS_Union( signed_message *sig_share) {

    /* Store the sig share */

    sig_share_message *share_specific;	
    signed_message *ccs_union;
    ccs_union_message *ccs_union_specific;
    int32u context, server_id;
    signed_message *new_ccs_union;

    share_specific = (sig_share_message*)(sig_share+1);
    ccs_union = (signed_message*)(share_specific+1);
    ccs_union_specific = (ccs_union_message*)(ccs_union+1);

    context = ccs_union_specific->context; 
    server_id = sig_share->machine_id;

    if ( CCS_UNION_SIG_SHARE[context][server_id] == NULL ) {
	inc_ref_cnt(sig_share);
 	CCS_UNION_SIG_SHARE[context][server_id] = sig_share;
	/* Now check to see if we have enough sig shares to compute signature
	 * */
 	if ( CCS_UNION_MESSAGE[context] == NULL && 
		CCS_Union_Message_Ready(context) ) {
	    new_ccs_union = APPLY_Generate_CCS_Union(context);
	    if ( new_ccs_union != NULL ) {
		/* Do something with the ccs_union message */
		if ( CCS_UNION_MESSAGE[context] != NULL ) {
		    dec_ref_cnt( CCS_UNION_MESSAGE[context] );
		}
		CCS_UNION_MESSAGE[context] = new_ccs_union;
		CCS_Handle_Union_Message( new_ccs_union );
	    }
	}
    }

}

int32u CCS_Union_Message_Ready( int32u context ) {

    int32u si;
    int32u count;

    count = 0;

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	if ( CCS_UNION_SIG_SHARE[context][si] ) {
	    count++;
	}
    }

    if ( count >= 2*VAR.Faults+1 ) {
	return 1;
    }
    return 0;

}

void APPLY_Proposal( signed_message *proposal ) {
    /* Put the proposal into the correct slot */
    pending_slot_struct *pslot;
    global_slot_struct *gslot;
    proposal_message *proposal_specific;
 
    proposal_specific = (proposal_message*)(proposal+1);
    
    /* First put the proposal into the global slot */

    gslot = UTIL_Get_Global_Slot( proposal_specific->seq_num );

    Alarm(DEBUG,"%d %d APPLY_Proposal %d %d seq: %d len:%d\n",
	    VAR.My_Site_ID,VAR.My_Server_ID
	    ,GLOBAL.View,UTIL_I_Am_In_Leader_Site(),
	     proposal_specific->seq_num, proposal->len );
   
    /* Store the proposal */
    if ( gslot->proposal == NULL ) {
	inc_ref_cnt(proposal);
	gslot->proposal = proposal;
    } else {
	/* Replace if this proposal has a more recent global view */
	if ( ((proposal_message*)(gslot->proposal + 1))->global_view
	     < proposal_specific->global_view ) {
	    dec_ref_cnt(gslot->proposal);
	    inc_ref_cnt(proposal);
	    gslot->proposal = proposal;
	}
    }

    /* Leader site */
    if ( UTIL_I_Am_In_Leader_Site() ) {
	/* Put the proposal in my pending data structures */
        pslot = UTIL_Get_Pending_Slot( proposal_specific->seq_num );
	Alarm(DEBUG,"Store proposal in pending_slot %d %d %d\n",
		proposal,VAR.My_Server_ID,proposal_specific->seq_num);
 	if ( pslot->proposal == NULL && 
	     proposal_specific->global_view == GLOBAL.View ) {
	    pslot->time_proposal_sent.sec = 0;
	    pslot->time_proposal_sent.usec = 0;
	    if ( proposal_specific->seq_num > PENDING.Max_ordered ) {
		PENDING.Max_ordered = proposal_specific->seq_num;
	    }
	    inc_ref_cnt(proposal);
	    pslot->proposal = proposal;
	    ASEQ_Update_ARU();
	}
	CCS_Report_Decider( PENDING_CONTEXT );
	CCS_Union_Decider( PENDING_CONTEXT );
    }

    CCS_Report_Decider( GLOBAL_CONTEXT );
    CCS_Union_Decider( GLOBAL_CONTEXT );

}

void APPLY_Accept( signed_message *accept ) {
    /* Put the accept into the correct slot */
    global_slot_struct *gslot;
    accept_message *accept_specific;
 
    accept_specific = (accept_message*)(accept+1);
    
    /* First put the accept into the global slot */

    gslot = UTIL_Get_Global_Slot( accept_specific->seq_num );

    Alarm(DEBUG,"%d %d APPLY_Accept gv: %d s: %d\n", VAR.My_Site_ID,
   	VAR.My_Server_ID, GLOBAL.View, accept_specific->seq_num );
   
    /* Store the accept */
    if ( gslot->accept[accept->site_id] == NULL ) {
	inc_ref_cnt(accept);
	gslot->accept[accept->site_id] = accept;
	/* Forward the accept */
	if ( UTIL_I_Am_Representative() ) {
	    UTIL_Site_Broadcast( accept );
	}
    } else {
	/* Replace if this accept has a more recent global view */
	if ( ((accept_message*)(gslot->accept[accept->site_id] + 1))->global_view
	     < accept_specific->global_view ) {
	    dec_ref_cnt(gslot->accept[accept->site_id]);
	    inc_ref_cnt(accept);
	    gslot->accept[accept->site_id] = accept;
	}
    }

    if ( APPLY_Global_Order_Ready( gslot ) ) {
	
	Alarm(DEBUG,"%d %d Recv Accept, Globally ordered: sn %d\n", 
		VAR.My_Site_ID, VAR.My_Server_ID, accept_specific->seq_num );
	GLOBO_Handle_Global_Ordering( gslot );
    }
 
}

void APPLY_Global_View_Change( signed_message *new_gvc ) {

    signed_message *old_gvc;
    
    old_gvc = GLOBAL.Global_VC[new_gvc->site_id];

    if ( GVC_Get_View( new_gvc ) > GVC_Get_View( old_gvc ) || 
	    GLOBAL.Global_VC[new_gvc->site_id] == NULL ) {
	/* The view of the new message is greater than the view of the old
	 * message. Replace the old message with the new one. */
	dec_ref_cnt( old_gvc );
	inc_ref_cnt( new_gvc );
	GLOBAL.Global_VC[new_gvc->site_id] = new_gvc;
    }
    
}

void APPLY_Local_View_Proof( signed_message *lv_proof ) {
    
    int32u old_lv, new_lv;

    old_lv = REP_Get_View_From_Proof(
	    PENDING.Local_view_proof[lv_proof->site_id]);
    
    new_lv = REP_Get_View_From_Proof(
	    lv_proof );

    Alarm(DEBUG,"%d %d APPLY_Local_View_Proof old %d new %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, old_lv, new_lv );

    if ( new_lv > old_lv ) {
	dec_ref_cnt( PENDING.Local_view_proof[lv_proof->site_id] );
	inc_ref_cnt( lv_proof );
	/* Store the proof */
	PENDING.Local_view_proof[lv_proof->site_id] = lv_proof;
    }

}

void APPLY_Update( signed_message *update ) {
    ;
}

void APPLY_L_New_Rep( signed_message *l_new_rep ) {

    /* The following contains logic that should probably be in the conflict
     * function. */
    
    int32u prev_view;
    int32u new_view;
   
    Alarm(DEBUG,"APPLY_L_New_Rep\n");
    
    new_view = REP_Get_Suggested_View(l_new_rep);
    prev_view = REP_Get_Suggested_View( PENDING.L_new_rep[l_new_rep->machine_id] ); 

    /* Store the l_new_rep message if it is for a view that is newer than the
     * view of the l_new_rep message that is stored now. */
    if ( new_view > prev_view ) {
	inc_ref_cnt( l_new_rep );
	PENDING.L_new_rep[l_new_rep->machine_id] = l_new_rep;
    }

}

/* Predicates */

int32u APPLY_Prepare_Matches_Pre_Prepare( signed_message *prepare, 
	signed_message *pre_prepare ) {

    pre_prepare_message *pre_prepare_specific;
    prepare_message *prepare_specific;
   
    byte digest[DIGEST_SIZE+1]; 

    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);
    prepare_specific = (prepare_message*)(prepare+1);


    if ( prepare == NULL || pre_prepare == NULL ) {
	return 0;
    }

    Alarm(DEBUG,"1\n");

    if ( pre_prepare_specific->local_view != 
         prepare_specific->local_view ) {
	Alarm(DEBUG,"lv %d %d %d %d\n",
		pre_prepare_specific->local_view, 
		prepare_specific->local_view,
	        prepare_specific->global_view,
	        prepare_specific->seq_num );
	return 0;
    }

    Alarm(DEBUG,"2\n");

    if ( pre_prepare_specific->global_view != 
         prepare_specific->global_view ) {
	return 0;
    }

    Alarm(DEBUG,"3\n");

    if ( pre_prepare_specific->seq_num != 
         prepare_specific->seq_num ) {
	return 0;
    }

    Alarm(DEBUG,"4\n");

    if ( pre_prepare_specific->seq_num != 
         prepare_specific->seq_num ) {
	return 0;
    }

    /* Make a digest of the update in the pre_prepare */
    /* Now compute the digest of the update and copy it into the digest field */
    OPENSSL_RSA_Make_Digest( 
	    (byte*)(pre_prepare_specific+1), 
	    pre_prepare->len - sizeof(pre_prepare_message), 
	    digest );

    Alarm(DEBUG,"5\n");

    if ( !OPENSSL_RSA_Digests_Equal(digest, 
		prepare_specific->update_digest) ) {
	return 0;
    }

    Alarm(DEBUG,"6\n");

    return 1;

}

int32u APPLY_Prepare_Certificate_Ready( signed_message *pre_prepare,
       signed_message **prepare, int32u alert_mismatch) {
    
    int32u pcount;
    int32u sn;
    pre_prepare_message *pre_prepare_specific; 
    
    pending_slot_struct *slot;

    pcount = 0;
    
    if ( pre_prepare == NULL  ) {
	return 0;
    }
   
    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);

    for ( sn = 1; sn <= NUM_SERVERS_IN_SITE; sn++ ) {
	if ( prepare[sn] != NULL ) {
	    if ( APPLY_Prepare_Matches_Pre_Prepare(prepare[sn], pre_prepare) ) 
	    { 
		pcount++;
	    } else if (alert_mismatch) {
		slot = UTIL_Get_Pending_Slot_If_Exists(
			pre_prepare_specific->seq_num );
		if ( slot != NULL ) {
		    Alarm(DEBUG,"SLOT: %d %d ",
			    slot, slot->prepare_certificate.pre_prepare );
		    if (slot->prepare_certificate.pre_prepare != NULL ) {
			pre_prepare_specific = (pre_prepare_message*)
			    (slot->prepare_certificate.pre_prepare + 1);
			Alarm(DEBUG,"pcert: %d %d\n",
				pre_prepare_specific->local_view,
				pre_prepare_specific->seq_num );
		    }	
		}
		Alarm(/*EXIT*/DEBUG,"PREPARE didn't match pre-prepare while "
		       "checking for prepare certificate.\n");
		return 0;
	    }
    	}
    }

    /* Sanity */
    

    Alarm(DEBUG,"%d %d pcount %d\n", 
	    VAR.My_Site_ID, VAR.My_Server_ID, pcount);

    if ( pcount >= VAR.Faults * 2 ) {
	Alarm(DEBUG,"%d %d pcount %d\n", 
	    VAR.My_Site_ID, VAR.My_Server_ID, pcount);

	return 1;
    }
    
    return 0;
}

int32u APPLY_Pending_Order_Ready( pending_slot_struct* slot ) {
    
    /* Count the number of shares -- if there are 2f + 1 shares, then true */

    int32u scount;
    int32u si;
    proposal_message *proposal_specific;
    signed_message *proposal;

    scount = 0;
    
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	if ( slot->sig_share[si] != NULL ) {
	    proposal = APPLY_Get_Content_Message_From_Sig_Share( 
		    slot->sig_share[si] );
	    proposal_specific = (proposal_message*)(proposal+1);
	    if ( proposal_specific->local_view == PENDING.View
	         && proposal_specific->global_view == GLOBAL.View ) {
		scount++;
	    } else {
		dec_ref_cnt( slot->sig_share[si] );
		slot->sig_share[si] = NULL;
	    }
	}
    }
 
    Alarm(DEBUG,"%d %d\n", scount, 2*VAR.Faults+1);

    if ( scount >= 2*VAR.Faults+1 ) {
	return 1;
    }

    return 0;

}

int32u APPLY_Accept_Ready( global_slot_struct* slot ) {
    
    /* Count the number of shares -- if there are 2f + 1 shares, then true */

    int32u scount;
    int32u si;

    Alarm(DEBUG,"APPLY_Accept_Ready\n");
    
    scount = 0;
    
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	if ( slot->accept_share[si] != NULL ) {
	    scount++;
	}
    }
 
    Alarm(DEBUG,"count %d\n",scount);
    
    if ( scount >= 2*VAR.Faults+1 ) {
	return 1;
    }

    return 0;
}

int32u APPLY_Global_Order_Ready( global_slot_struct *slot ) {
    /* Is the update globally ordered? */
    int32u si;
    int32u acount;
    accept_message *accept_specific;

    if ( slot->proposal == NULL ) {
	return 0;
    }
    
    acount = 1; /* The proposal counts as an Accept */
    for ( si = 1; si <= NUM_SITES; si++ ) {
	if ( slot->accept[si] != NULL ) {
	    accept_specific = (accept_message*)(slot->accept[si]+1);
	    Alarm(DEBUG,"Checcking Accept %d %d %d %d\n", 
		    si, slot->accept[si],
		    slot->accept[si]->site_id, accept_specific->seq_num);
	    acount++;
	}
    }
   
    /* We have a majority */
    if ( acount > NUM_SITES / 2 ) {
	Alarm(DEBUG,"Globally order returning 1\n");
	return 1;
    }
    
    return 0;
}

/* Other functions */
void APPLY_Move_Prepare_Certificate( signed_message **pre_prepare_src,
	signed_message **prepare_src, pending_slot_struct *slot ) {

    int32u pcount;
    int32u sn;

    Alarm(DEBUG,"made prepare cert\n");

    pcount = 0;

    slot->prepare_certificate.pre_prepare = *pre_prepare_src;
    *pre_prepare_src = NULL;
    
    for ( sn = 1; sn <= NUM_SERVERS_IN_SITE; sn++ ) {
	if ( (prepare_src)[sn] != NULL ) {
	    Alarm(DEBUG,"APPLY_Move_Prepare_Certificate %d\n",prepare_src[sn]);
	    if ( APPLY_Prepare_Matches_Pre_Prepare(
			prepare_src[sn],
			slot->prepare_certificate.pre_prepare
			 ) ) { 
		slot->prepare_certificate.prepare[sn] = (prepare_src)[sn];
		(prepare_src)[sn] = NULL;
	    } else {
	      Alarm(/*EXIT*/DEBUG,"PREPARE didn't match pre-prepare while "
		       "moving prepare certificate.\n");
	      return;
	    }
    	}
    }

    /* The next time that the ASEQ code processes a prepare, it should
     * send a signature share */
    
    slot->send_sig_share_on_prepare = 1;

}

signed_message* APPLY_Generate_Proposal( pending_slot_struct *slot) {

    /* This function should only be called if there are enough signature shares
     * to generate a proposal. If all of the shares are good, a valid signature
     * for a proposal can be generated. However, if any of the shares are bad,
     * we must identify any bad shares and add them to a blacklist. 
     * The blacklisting code is not currently implemented. */

    signed_message *proposal;
    int32u combine_success;
    int32u c;
    
    /* Make a new Proposal message */
    proposal = UTIL_New_Signed_Message();

    for ( c=1; c<=NUM_SERVERS_IN_SITE; c++  ) {
	Alarm(DEBUG,"%d\n",slot->sig_share[c]);
    }
    
    /* Call THRESH to combine threshold signature */
    combine_success = THRESH_Attempt_To_Combine( 
	    slot->sig_share, 
	    proposal ); 
    
    if ( combine_success ) {
	/* Add proposal to the data structure */ 
	return proposal;
    } else {
	dec_ref_cnt( proposal );
    }

    Alarm(DEBUG,"Failed to combine proposal!!!!!!\n");
    return NULL;
}

signed_message* APPLY_Generate_Accept( global_slot_struct *slot) {
    
    /* This function should only be called if there are enough signature shares
     * to generate a proposal. If all of the shares are good, a valid signature
     * for a proposal can be generated. However, if any of the shares are bad,
     * we must identify any bad shares and add them to a blacklist. 
     * The blacklisting code is not currently implemented.  */

    signed_message *accept;
    int32u combine_success;
    int32u c;

    Alarm(DEBUG,"APPLY_Generate_Accept\n");
    
    /* Make a new Proposal message */
    accept = UTIL_New_Signed_Message();

    for ( c=1; c<=NUM_SERVERS_IN_SITE; c++  ) {
	Alarm(DEBUG,"%d\n",slot->accept_share[c]);
    }
    
    /* Call THRESH to combine threshold signature */
    combine_success = THRESH_Attempt_To_Combine( 
	    slot->accept_share, 
	    accept ); 

    if ( combine_success ) {
	/* Add proposal to the data structure */ 
	return accept;
    } else {
	dec_ref_cnt( accept );
    }
    return NULL;

}

signed_message* APPLY_Generate_Global_View_Change() {
    
    /* This function should only be called if there are enough signature shares
     * to generate a global view change message. If all of the shares are good,
     * a valid signature for a proposal can be generated. However, if any of
     * the shares are bad, we must identify any bad shares and add them to a
     * blacklist. 
     * The blacklisting code is not currently implemented. */

    signed_message *global_vc;
    int32u combine_success;
    int32u i;
    signed_message* sig_share_to_combine[NUM_SERVER_SLOTS];
    signed_message *share, *my_share;
    int32u my_global_view;

    Alarm(DEBUG,"APPLY_Generate_Global_View_Change\n");
    
    /* Make a new global vc message */
    global_vc = UTIL_New_Signed_Message();

    /* Get my share */
    my_share = GLOBAL.Global_VC_share[VAR.My_Server_ID];
    
    /* Get my share view number */
    my_global_view = GVC_Get_View( 
	    APPLY_Get_Content_Message_From_Sig_Share( my_share ) );

    Alarm(DEBUG,"My gv %d\n",my_global_view);

    /* Copy any sig shares that are the same as mine into a new array. */
    for ( i=1; i<=NUM_SERVERS_IN_SITE; i++  ) {
	sig_share_to_combine[ i ] = NULL; /* Init the list */
	share = GLOBAL.Global_VC_share[i]; 
	if ( my_global_view == GVC_Get_View( 
	    APPLY_Get_Content_Message_From_Sig_Share( share ) ) ) {
	    sig_share_to_combine[i] = share;
	    Alarm(DEBUG,"Sig share for global_view_change from %d with v = "
		  "%d\n",
		  share->machine_id, GVC_Get_View( 
	    APPLY_Get_Content_Message_From_Sig_Share( share ) ) );
	}

    }
    
    /* Call THRESH to combine threshold signature */
    combine_success = THRESH_Attempt_To_Combine(
	    sig_share_to_combine,
	    global_vc );

    if ( combine_success ) {
	/* Add the global view change message to the data structure */ 
	return global_vc;
    } else {
	dec_ref_cnt( global_vc );
    }
    return NULL;
}

signed_message* APPLY_Generate_Local_View_Proof() {

    /* This function should only be called if there are enough signature shares
     * to generate a global view change message. If all of the shares are good,
     * a valid signature for a proposal can be generated. However, if any of
     * the shares are bad, we must identify any bad shares and add them to a
     * blacklist. 
     * The blacklisting code is not currently implemented. */

    signed_message *local_view_proof;
    int32u combine_success;
    int32u i;
    signed_message* sig_share_to_combine[NUM_SERVER_SLOTS];
    signed_message *share, *my_share;
    int32u my_local_view;

    Alarm(DEBUG,"APPLY_Generate_Local_View_Proof\n");
    
    /* Make a new global vc message */
    local_view_proof = UTIL_New_Signed_Message();

    /* Get my share */
    my_share = PENDING.Local_view_proof_share[VAR.My_Server_ID];
    
    /* Get my share view number */
    my_local_view = REP_Get_View_From_Proof( 
	    APPLY_Get_Content_Message_From_Sig_Share( my_share ) );

    Alarm(DEBUG,"My local view %d\n",my_local_view);

    /* Copy any sig shares that are the same as mine into a new array. */
    for ( i=1; i<=NUM_SERVERS_IN_SITE; i++  ) {
	sig_share_to_combine[ i ] = NULL; /* Init the list */
	share = PENDING.Local_view_proof_share[i]; 
	if ( my_local_view == REP_Get_View_From_Proof( 
	    APPLY_Get_Content_Message_From_Sig_Share( share ) ) ) {
	    sig_share_to_combine[i] = share;
	    Alarm(DEBUG,"Sig share for local_view_proof from %d with v = %d\n",
		share->machine_id, REP_Get_View_From_Proof( 
	    APPLY_Get_Content_Message_From_Sig_Share( share ) ) );
	}

    }
    
    /* Call THRESH to combine threshold signature */
    combine_success = THRESH_Attempt_To_Combine(
	    sig_share_to_combine,
	    local_view_proof );

    if ( combine_success ) {
	/* Add the global view change message to the data structure */ 
	return local_view_proof;
    } else {
	dec_ref_cnt( local_view_proof );
    }
    return NULL;
}

signed_message* APPLY_Generate_CCS_Union( int32u context ) {
    
    /* This function should only be called if there are enough
     * signature shares to generate a ccs union. If all of the shares
     * are good, a valid signature for a ccs union can be
     * generated. However, if any of the shares are bad, we must
     * identify any bad shares and add them to a blacklist.  
     * The blacklisting code is not currently implemented. */

    signed_message *ccs_union;
    int32u combine_success;

    Alarm(DEBUG,"APPLY_Generate_CCS_Union_Message\n");
 
    /* Make a new ccs union message */
    ccs_union = UTIL_New_Signed_Message();

    /* Call THRESH to combine threshold signature */
    combine_success = THRESH_Attempt_To_Combine( 
	    CCS_UNION_SIG_SHARE[context], 
	    ccs_union ); 

    if ( combine_success ) {
	/* Add proposal to the data structure */ 
	return ccs_union;
    } else {
	dec_ref_cnt( ccs_union );
    }
 
    return NULL;
}
