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

/* Protocol ASSIGN-SEQUENCE. The functions in this code implement
 * Protocol Assign-Seq as described in the technical report. */

#include "assign_sequence.h" 
#include "error_wrapper.h"
#include "utility.h"
#include "apply.h"
#include "openssl_rsa.h"
#include "util/arch.h"
#include "util/alarm.h"
#include "util/memory.h"
#include "threshold_sign.h"
#include "local_reconciliation.h"
#include "timeouts.h"
#include "network.h"
#include "construct_collective_state_protocol.h"
#include <string.h>

/* Globally Accessible Variables */

extern server_variables VAR;
extern global_data_struct GLOBAL;
extern pending_data_struct PENDING;
extern client_data_struct CLIENT;

/* Local Functions */
void ASEQ_Upon_Receiving_Pre_Prepare( signed_message *mess ); 
void ASEQ_Upon_Receiving_Prepare( signed_message *mess ); 
void ASEQ_Send_Pre_Prepare( signed_message *mess, int32u seq_num ); 
void ASEQ_Retransmit(int dummy, void *dummyp );
void ASEQ_Add_Update_To_Queue( signed_message *mess ); 
void ASEQ_Add_Proposal_To_Queue( signed_message *mess ); 
void ASEQ_Process_Update_From_Client( signed_message *mess ); 
int32u ASEQ_Okay_To_Send_Next_Proposal_On_Wide_Area(); 
int32u ASEQ_Okay_To_Send_Next_Pre_Prepare_On_Local_Area();
void ASEQ_Attempt_To_Send_Proposal( int dummy, void *dummpy ); 
/* Process an update in ASEQ. */
void ASEQ_Process_Update( signed_message *mess ); 

/* Checks to see if we should play the ASEQ protocol */
int32u ASEQ_Is_Constrained(); 
int32u ASEQ_Seq_Num_Within_My_Response_Window( int32u seq_num );

/* Message construction and sending */
signed_message* ASEQ_Construct_Pre_Prepare( signed_message *mess,
		    int32u seq_num ); 
signed_message* ASEQ_Construct_Prepare( signed_message *mess );
signed_message* ASEQ_Construct_Proposal(signed_message *mess);

/* Garbage collection */
void ASEQ_Garbage_Collect_Prepare_Certificate( prepare_certificate_struct *pcert);
void ASEQ_Garbage_Collect_Pending_Slot( pending_slot_struct *slot ); 

/* Local Variables */

/* A stopwatch used for timing during tests. */
util_stopwatch w;

util_stopwatch speed_stop_watch;

util_stopwatch send_proposal_stopwatch;

/* A queue of messages. */
dll_struct update_dll;
dll_struct proposal_dll;

/* Protocol 1 Normal Case Functions */

/* Dispatches a valid signed message to an appropriate function which
 * corresponds to our Assign-Seq pseudocode. */
void ASEQ_Dispatcher( signed_message *mess ) {

    /* All messages are of type signed_message. We assume that: 
     * 
     * THERE ARE NO CONFLICTS
     *
     * THE MESSAGE HAS BEEN APPLIED TO THE DATA STRUCTURE
     *
     * THE MESSAGE HAS PASSED VALIDATION
     */
    switch ( mess->type ) {
	case UPDATE_TYPE :
	    ASEQ_Process_Update_From_Client( mess );
	    return;
	case PRE_PREPARE_TYPE :
	    ASEQ_Upon_Receiving_Pre_Prepare( mess );
	    return;
	case PREPARE_TYPE :
	    ASEQ_Upon_Receiving_Prepare( mess );
	    return;
	default:
	    INVALID_MESSAGE("");
    } 	    
	
}

/* Process an update that comes directly from a client. An update can also be
 * processed when updates are replayed after a view change. */
void ASEQ_Process_Update_From_Client( signed_message *update ) {

    int32u cli_id;
    int32u site_id;

    cli_id = update->machine_id;
    site_id = update->site_id;

    if ( update->site_id > 0 )
        Alarm(ASEQ_PRINT,"%d %d Process update from client(%d,%d) gs:%d "
	    "garu:%d paru:%d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, 
	    site_id, cli_id, VAR.Global_seq,
	    GLOBAL.ARU, PENDING.ARU );

    if ( cli_id == 0 || cli_id > NUM_CLIENTS || 
	    site_id == 0 || site_id > NUM_SITES ) {
	Alarm(ASEQ_PRINT,"ASEQ_Process_Update_From_Client: "
		"Received invalid client message.\n");
	return;
    }

    /* The Following function will process the update: 
     *
     * 1) Forward it to leader rep if necessary
     *
     * 2) Decide if it should be injected 
     *
     * 3) Send a response to client if this update has already been globally
     * ordered. 
     * */

    if ( UTIL_CLIENT_Process_Update( update ) ) {
	/* I am in the leader site AND I should put update into the system */
	/* First add the update to the queue. */
    	if ( update->site_id > 0 )
	    Alarm(ASEQ_PRINT,"Adding update to queue\n");	
	ASEQ_Add_Update_To_Queue( update );
	/* Then process any updates in the queue. */
	ASEQ_Process_Next_Update();
    }

}

/* Add a message from the client to the update_dll. This data structure stores
 * messages that come from clients. */
void ASEQ_Add_Update_To_Queue( signed_message *mess ) {

    UTIL_DLL_Add_Data( &update_dll, mess );

    UTIL_DLL_Set_Last_Int32u_1( &update_dll, 0 );
 
}

/* Add a message to the proposal queue. This data structure stores
 * messages that come from the site -- threshold signed proposals. */
void ASEQ_Add_Proposal_To_Queue( signed_message *mess )   {

    UTIL_DLL_Add_Data( &proposal_dll, mess );

}

signed_message* ASEQ_Get_Constrained_Update_If_Exists( int32u seq ) {

    /* Do I have knowledge of an update that should be bound to the next
     * sequence number? */

    global_slot_struct *gslot;
    pending_slot_struct *pslot;

    signed_message *update;
    signed_message *gpro;
    signed_message *ppro;

    proposal_message *ppro_specific;
    proposal_message *gpro_specific;
    pre_prepare_message *pre_prepare_specific;

    update = NULL;
    gpro = NULL;
    ppro = NULL;

    gslot = UTIL_Get_Global_Slot_If_Exists( seq );
    pslot = UTIL_Get_Pending_Slot_If_Exists( seq );

    if ( gslot != NULL ) {
	/* Do we have a proposal in the global data structure? */
	gpro = gslot->proposal;
    }

    if ( pslot != NULL ) {
	ppro = pslot->proposal;
    }

    /* If we have proposals in both slots, then figure out which one has the
     * highest global view and get the update from this one. */
    if ( gpro != NULL && ppro != NULL ) {
	/* Check the views */
	gpro_specific = (proposal_message*)(gpro+1);
	ppro_specific = (proposal_message*)(ppro+1);
	/* Sanity check -- are the updates identical -- we should insure that
	 * the updates are identical. */
	if ( ppro->len != gpro->len ) {
	    Alarm(/*EXIT*/ASEQ_PRINT,"I had two a proposal stored in the pending context "
		    "that had a different length than the proposal stored "
		    "in the global context. %d %d\n", ppro->len,
		    gpro->len ); 
	}
	if ( memcmp( (byte*)(ppro_specific+1), 
		     (byte*)(gpro_specific+1),
		     ppro->len - (sizeof(proposal_message)) ) != 0 ) {
	    Alarm(/*EXIT*/ASEQ_PRINT,"I had a proposal in the pending context that was "
		    "different than the proposal in the global context.\n"
		    "gpro: lv %d gv %d seq %d ppro: lv %d gv %d seq %d\n",
		    gpro_specific->local_view, gpro_specific->global_view, 
		    gpro_specific->seq_num,
		    ppro_specific->local_view, ppro_specific->global_view, 
		    ppro_specific->seq_num );
	    /* We should ensure that this never happens. */
	}
	/* We will return the update bound to the highes view. Note that it
	 * should not matter which one is returned. However, in case there is
	 * an error in purging the data structs, the one with the higher view
	 * is the correct one. */
	if ( gpro_specific->global_view >= ppro_specific->global_view ) {
	    return (signed_message*)(gpro_specific+1);
	}
	return (signed_message*)(ppro_specific+1);
    }

    if ( gpro != NULL ) {
	gpro_specific = (proposal_message*)(gpro+1);
	/* Return the update associated with this proposal */
	return (signed_message*)(gpro_specific+1);
    }

    if ( ppro != NULL ) {
	ppro_specific = (proposal_message*)(ppro+1);
	/* Return the update associated with this proposal */
	return (signed_message*)(ppro_specific+1);
    }
   
    /* WE DO NOT HAVE ANY PROPOSALS, but we may have a prepare certificate.
     * Check if we have a prepare certificate. */
    if ( pslot != NULL ) {
	if ( pslot->prepare_certificate.pre_prepare != NULL ) {
	    pre_prepare_specific = (pre_prepare_message*)
		(pslot->prepare_certificate.pre_prepare + 1); 
	    return (signed_message*)(pre_prepare_specific+1);
	}
    }

    /* I do not have anything */
    return NULL;
}

/* Process the next update in the queue if the queue is not empty. */
void ASEQ_Process_Next_Update() {

    signed_message *next;
    int32u seq_num;
    int32u count;
    signed_message *constrained_update;

    if ( !(UTIL_I_Am_Representative() && UTIL_I_Am_In_Leader_Site()) ) {
	return;
    }

    Alarm(ASEQ_PRINT,"PROCESS NEXT UPDATE empty:u%d p%d okay:%d\n", 
		UTIL_DLL_Is_Empty( &update_dll ),
		UTIL_DLL_Is_Empty( &proposal_dll ),
		ASEQ_Okay_To_Send_Next_Pre_Prepare_On_Local_Area());

    if ( GLOBAL.ARU > VAR.Global_seq ) {
	VAR.Global_seq = GLOBAL.ARU;
    }

    if ( GLOBAL.ARU > PENDING.ARU ) {
	PENDING.ARU = GLOBAL.ARU;
    }

    count = 0;
    while ( ASEQ_Okay_To_Send_Next_Pre_Prepare_On_Local_Area() ) {
	/* At this point, we are constrained and we must check to make sure
	 * that we send a valid update. */
	constrained_update = ASEQ_Get_Constrained_Update_If_Exists( 
		VAR.Global_seq + 1 );
	if ( constrained_update != NULL ) {
	    /* There is already an update that has been bound to this sequence
	     * number, therefore we need to inject it into the system and not
	     * one of the updates in our queue. */
	    Alarm(ASEQ_PRINT,"\n********* REPLAY %d **********\n\n", VAR.Global_seq
		    + 1 );
	    ASEQ_Process_Update( constrained_update );
	} else {    
	    next = UTIL_DLL_Front_Message( &update_dll );
	    seq_num = UTIL_DLL_Front_Int32u_1( &update_dll );
	    ASEQ_Process_Update( next );
	    UTIL_DLL_Pop_Front( &update_dll );
	    count++;
	}
    }

    if ( count >= 2 ) {
	Alarm(DEBUG,"COUNT %d\n",count);
    }

}

void ASEQ_Attempt_To_Send_Proposal( int dummy, void *dummpy ) {

    ASEQ_Process_Next_Proposal();

}

int32u ASEQ_Okay_To_Send_Next_Proposal_On_Wide_Area() {

    /* Can the first proposal in queue be sent on the wide area? */

    signed_message *proposal;
    proposal_message *proposal_specific;
    /*proposal_message *temp;*/
#if 0
    sp_time to;
    double elapsed;
#endif

    if ( UTIL_DLL_Is_Empty( &proposal_dll ) ) {
	/* There is no message to send */
	return 0;
    }

    proposal = UTIL_DLL_Front_Message( &proposal_dll );

    proposal_specific = (proposal_message*)(proposal+1);

    if ( proposal_specific->seq_num >= GLOBAL.ARU + GLOBAL_WINDOW + 10000 ) {

	/* FINAL added a 10000 in the if statement above -- we won't use this
	 * window */

	/* The global window is full -- we should not send any more proposals
	 * until the global aru increases. */
	Alarm(ASEQ_PRINT,"Global Window Full %d %d\n",
	      proposal_specific->seq_num, GLOBAL.ARU );
	/* FINAL */
#if 0
	UTIL_DLL_Set_Begin(&proposal_dll);
	while ( !UTIL_DLL_At_End(&proposal_dll) ) {
	    temp = (proposal_message*)( UTIL_DLL_Get_Signed_Message(
			&proposal_dll ) + 1 );
	    Alarm(PRINT,"   SEQ NUM %d\n", temp->seq_num );
	    UTIL_DLL_Next( &proposal_dll );
	    
	}
	Alarm(DEBUG,"x");
#endif
	return 0;
    } 
   
#if 0
    /* To throttle sending of Proposal messages */
    UTIL_Stopwatch_Stop(&send_proposal_stopwatch);

    elapsed = UTIL_Stopwatch_Elapsed(&send_proposal_stopwatch); 

    if ( elapsed < 0.008 ) {
	to.sec = 0;
	to.usec = 8100 - ( (int32u)(elapsed * 1000000) ); 
	E_queue( ASEQ_Attempt_To_Send_Proposal, 
		0, NULL, to );
	return 0;
    }
#endif

    return 1;
 
}

/* Send the next proposals in the queue if the queue is not empty. */
void ASEQ_Process_Next_Proposal() {

    signed_message *next;

    while ( ASEQ_Okay_To_Send_Next_Proposal_On_Wide_Area() ) {
      	next = UTIL_DLL_Front_Message( &proposal_dll );
	/* Send the proposal */
	Alarm(ASEQ_PRINT,"Send proposal\n");

	UTIL_Stopwatch_Stop( &send_proposal_stopwatch );
	Alarm(ASEQ_PRINT,"*********************************** %f\n",
		UTIL_Stopwatch_Elapsed( &send_proposal_stopwatch ) );


	UTIL_Stopwatch_Start(&send_proposal_stopwatch);

	UTIL_Send_To_Site_Representatives( next );
 	UTIL_DLL_Pop_Front( &proposal_dll );
    }

}

/* Check to determine if I am properly constrained. */
int32u ASEQ_Is_Constrained() {

    if ( !CCS_Am_I_Constrained_In_Pending_Context() ) {
	Alarm(ASEQ_PRINT,"ASEQ: I am not constrained in the pending context.\n");
	return 0;
    }

    if ( !CCS_Is_Globally_Constrained() ) {
	Alarm(ASEQ_PRINT,"ASEQ: I am not constrained in the global context.\n");
	return 0;
    }

    /* Both constrint checks passed, we are globally constrained and can
     * participate in ASEQ */
    return 1;

}

int32u ASEQ_Okay_To_Send_Next_Pre_Prepare_On_Local_Area() {

    /* Can the first update in queue be sent as a pre_prepare? This function
     * returns 1 if it is okay to send a pre_prepare and it returns 0 if not.
     * */

    if ( UTIL_DLL_Is_Empty( &update_dll ) ) {
	/* There is no message to send */
	return 0;
    }

    /* Check both local and global windows */
    if ( VAR.Global_seq >= PENDING.ARU + LOCAL_WINDOW
	 || VAR.Global_seq >= GLOBAL.ARU + GLOBAL_WINDOW ) {
	/* The local window is full -- we should not send any more pre-prepares
	 * until the global aru increases. */
	Alarm(ASEQ_PRINT,"Local Window Full %d g.aru: %d p.aru %d\n",
	      VAR.Global_seq, GLOBAL.ARU, PENDING.ARU );
	return 0;
    } 

    if ( !ASEQ_Is_Constrained() ) {
	/* I am not constrained, so I cannot send a message. */
	Alarm(ASEQ_PRINT,"ASEQ: Not constrained so cannot send a pre_prepare.\n");
	return 0;
    }
 
    return 1;
 
}

/* Process an update. */
void ASEQ_Process_Update( signed_message *mess ) {

    int32u bind_seq_num;
    signed_message *pre_prepare;
    pending_slot_struct *slot;

    Alarm(DEBUG,"%d %d ASEQ_Process_Update from %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, mess->machine_id );

    if ( UTIL_I_Am_Representative() ) {
	VAR.Global_seq++;
	bind_seq_num = VAR.Global_seq;
	UTIL_Stopwatch_Start(&w);
	/* Construct and send a Pre-Prepare message */
	Alarm(ASEQ_PRINT,"%d ASEQ_Process_Update (sending pre-prepare) %d %d gv %d\n",
		VAR.My_Server_ID,VAR.Global_seq,bind_seq_num,GLOBAL.View);
 	pre_prepare = ASEQ_Construct_Pre_Prepare( mess, bind_seq_num );
	APPLY_Message_To_Data_Structs( pre_prepare );
	slot = UTIL_Get_Pending_Slot( bind_seq_num );
	slot->time_pre_prepare_sent = E_get_time();
        /* if ( rand() % 100 > 10 ) { */
	UTIL_Site_Broadcast( pre_prepare );
	dec_ref_cnt( pre_prepare );
	/* } */
    } 
}

void ASEQ_Upon_Receiving_Pre_Prepare( signed_message *mess ) {

    signed_message *prepare;
    pending_slot_struct *slot;
    pre_prepare_message *pre_prepare_specific;
    pre_prepare_message *old_pre_prepare_specific;

    int32u view;

    /* If I am the representative, I generated the pre-prepare and it serves as
     * a Prepare message */

    if ( GLOBAL.ARU > PENDING.ARU ) {
	PENDING.ARU = GLOBAL.ARU;
    }

    if ( UTIL_I_Am_Representative() ) {
	return;
    }

    if ( !ASEQ_Is_Constrained() ) {
	/* I am not constrained, so I cannot send a message. */
	Alarm(ASEQ_PRINT,"Received pre_prepare but I am not constrained.\n");
	return;
    }

    pre_prepare_specific = (pre_prepare_message*)(mess+1);

    if ( !ASEQ_Seq_Num_Within_My_Response_Window( 
		pre_prepare_specific->seq_num ) ) {
    	
	Alarm(ASEQ_PRINT,"%d %d Pre_Prepare seq num not within my response"
		" window\n", VAR.My_Site_ID, VAR.My_Server_ID );
	
	return;
    }

    /* Check if I already have a pre_prepare */
    slot = UTIL_Get_Pending_Slot_If_Exists( pre_prepare_specific->seq_num );

    /* Retransmission logic */
    if ( slot != NULL ) {
	if ( slot->proposal != NULL ) {
	    /* We have a proposal, so we send it and return */
	    UTIL_Site_Broadcast( slot->proposal );
	    return;
	}
	if ( slot->prepare_certificate.pre_prepare != NULL ) {
	    /* This prepare certificate may be from an old view. If so, I need
	     * to send a prepare BASED on the new view. If the prepare
	     * certificate is from my current view, then I can resend my
	     * current sig_share for this prepare certificate and I resend my
	     * own prepare. */
	    old_pre_prepare_specific = (pre_prepare_message*)
		(slot->prepare_certificate.pre_prepare+1);
	    if ( PENDING.View == old_pre_prepare_specific->local_view ) {
		if ( slot->sig_share[VAR.My_Server_ID] != NULL ) {

		    /* Sanity check */
		    view = ((proposal_message*)
			  (APPLY_Get_Content_Message_From_Sig_Share( 
			   slot->sig_share[VAR.My_Server_ID]  ) + 1))
			    ->local_view;
		    
		    if ( view != PENDING.View ){
			Alarm(/*EXIT*/ASEQ_PRINT,"SENDING SIG SHARE THAT IS NOT FROM MY VIEW"
				"%d %d\n", view, PENDING.View );
		    }

		    UTIL_Site_Broadcast(
			slot->sig_share[VAR.My_Server_ID] );
		}
		if ( slot->prepare_certificate.prepare[VAR.My_Server_ID] !=
			NULL ) {
		    UTIL_Site_Broadcast( 
			slot->prepare_certificate.prepare[VAR.My_Server_ID] );
		    return;
		}
	    }
	}
	if ( slot->prepare[VAR.My_Server_ID] != NULL ) {
	    UTIL_Site_Broadcast( slot->prepare[VAR.My_Server_ID] );
	    return;
	}
    }
    
    Alarm(DEBUG,"%d Received Pre-Prepare\n",VAR.My_Server_ID);
    
    /* Construct a Prepare Message based on the Pre-Prepare */
    prepare = ASEQ_Construct_Prepare( mess );

    Alarm(DEBUG,"%d %d %d\n",prepare->len,prepare->type,prepare->machine_id);
    
    /* Apply the my prepare (the one I just made) to the data structure */
    APPLY_Message_To_Data_Structs( prepare );

    Alarm(DEBUG,"%d %d Send prepare %d\n", VAR.My_Site_ID , VAR.My_Server_ID,
	    ((prepare_message*)(prepare+1))->seq_num );

    UTIL_Site_Broadcast( prepare );

    /* Apply will inc the ref count */
    dec_ref_cnt( prepare );

}

void ASEQ_Upon_Receiving_Prepare( signed_message *mess ) {
    /* Call function to determine if there is now a Prepare Certificate. */
    /* If prepare certificate, invoke Theshold-Signature */

    pending_slot_struct *slot;
    signed_message *proposal;
    prepare_message *prepare_specific;

    prepare_specific = (prepare_message*)(mess+1);

    slot = UTIL_Get_Pending_Slot_If_Exists( prepare_specific->seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( !ASEQ_Seq_Num_Within_My_Response_Window( 
		prepare_specific->seq_num ) ) {
    	
	Alarm( ASEQ_PRINT,"%d %d Prepare seq num not within my response"
		" window\n", VAR.My_Site_ID, VAR.My_Server_ID );
	
	return;
    }
   
    Alarm(DEBUG,"%d Received Prepare\n",VAR.My_Server_ID);
    
    if ( slot->prepare_certificate.pre_prepare != NULL ) {
	Alarm(DEBUG,"%d PREPARE_CERTIFICATE\n",VAR.My_Server_ID);
	/* Send threshold share only the first time that we have a prepare
	 * certificate */
	if ( slot->send_sig_share_on_prepare ) {
	    slot->send_sig_share_on_prepare = 0;
	    proposal = ASEQ_Construct_Proposal( 
		    slot->prepare_certificate.pre_prepare );
	    /* Send a sig share for the proposal */
	    if ( ((proposal_message*)(proposal+1))->seq_num !=
	         ((prepare_message*)(mess+1))->seq_num ) {
		/* Sanity */
		Alarm(DEBUG, "\n\n************** WARNING ****************\n" 
		"*** Generated Proposal Inconsistent with Prepare ****** %d %d \n\n",
		 ((proposal_message*)(proposal+1))->seq_num,
	         ((prepare_message*)(mess+1))->seq_num	 );
	    }
	    Alarm(DEBUG,"Invoke THRESH\n");
	    if ( slot->sig_share[VAR.My_Server_ID] == NULL ) {
		UTIL_Update_CCS_STATE_PENDING(
			((proposal_message*)(proposal+1))->seq_num ); 
		THRESH_Invoke_Threshold_Signature( proposal );
	    }

	    dec_ref_cnt(proposal);
	}
    }
}

void PRINT_Signed_Message( signed_message *mess ) {

    Alarm(PRINT," mid: %d sid: %d len: %d ",
	    mess->machine_id, mess->site_id, mess->len );
    
}

void PRINT_Proposal( signed_message *proposal ) {
    
    proposal_message *proposal_specific;
    
    proposal_specific = (proposal_message*)(proposal+1);
    
    Alarm( PRINT, "%d Proposal: ",VAR.My_Server_ID);
    
    PRINT_Signed_Message(proposal);

    Alarm( PRINT, "lv: %d gv: %d sn: %d\n",
	    proposal_specific->local_view, 
	    proposal_specific->global_view, 
	    proposal_specific->seq_num );
    
}

void ASEQ_Process_Proposal( signed_message *proposal ) {

    pending_slot_struct *slot;
    int32u seq_num; 

    ASEQ_Update_ARU();

    /* Perform necessary forwarding of proposal from the leader site onto the
     * wide area -- only the representative does forwarding and it only 
     * forwards if this is the first time that it has received the proposal. */

    if ( UTIL_I_Am_In_Leader_Site() && UTIL_I_Am_Representative() ) {
	/* Send the proposal on the wide area. */
	UTIL_Stopwatch_Stop(&w);
	seq_num = ((proposal_message*)(proposal+1))->seq_num;
	slot = UTIL_Get_Pending_Slot_If_Exists( 
	        seq_num );
	if ( slot != NULL ) {
	    if ( slot->time_proposal_sent.sec == 0 && 
		 slot->time_proposal_sent.usec == 0 ) { 
		slot->time_proposal_sent = E_get_time();
		UTIL_Site_Broadcast(proposal);
		//UTIL_Send_To_Site_Representatives(proposal);
		ASEQ_Add_Proposal_To_Queue(proposal);
		ASEQ_Process_Next_Proposal();
		Alarm(DEBUG,"SEND PRO ON WIDE AREA %d %f pend aru %d seq %d g aru %d\n", 
		    seq_num, UTIL_Stopwatch_Elapsed(&w),
		    PENDING.ARU, seq_num, GLOBAL.ARU );
	    }
	} else {
	  Alarm(DEBUG, "Tried to send NULL proposal\n");
	} 
    }
}

void ASEQ_Garbage_Collect_Prepare_Certificate( prepare_certificate_struct *pcert)
{

    int32u si;

    Alarm(DEBUG,"ASEQ_Garbage_Collect_Prepare_Cert %d\n",pcert);

    if ( pcert->pre_prepare != NULL ) {
	Alarm(DEBUG,"xx %d\n",pcert->pre_prepare);
	dec_ref_cnt( pcert->pre_prepare );
	pcert->pre_prepare = NULL;
    }

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) { 
	if ( pcert->prepare[si] != NULL ) {
	    Alarm(DEBUG,"GC pc prepare %d %d\n", si,
		    get_ref_cnt( pcert->prepare[si] ));
	    dec_ref_cnt( pcert->prepare[si] );
	    pcert->prepare[si] = NULL;
	}
    }	

}

void ASEQ_Garbage_Collect_Pending_Slot( pending_slot_struct *slot ) {
 
    /* Do garbage collection */
    
    /* The slot should be ordered */
    int32u si;

    if ( slot == NULL ) {
	return;
    }

    /* Free the pre_prepare */
    if ( slot->pre_prepare != NULL ) {
	Alarm(DEBUG,"xxx %d\n",slot->pre_prepare);
	dec_ref_cnt( slot->pre_prepare );
	slot->pre_prepare = NULL;
    }

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) { 
	/* Free the prepare messages */
	if ( slot->prepare[si] != NULL ) {
	    Alarm(DEBUG,"GC prepare %d %d\n", si,
		    get_ref_cnt( slot->prepare[si] ));
	    dec_ref_cnt( slot->prepare[si] );
	    slot->prepare[si] = NULL;
	}
	/* Free the sig_share messages */
	if ( slot->sig_share[si] != NULL ) {
	    Alarm(DEBUG,"GC sig_share %d %d\n", si,
		    get_ref_cnt( slot->sig_share[si] ));
	    dec_ref_cnt( slot->sig_share[si] );
	    slot->sig_share[si] = NULL;
	}
    }
    
    /* Free the prepare_certificate */
    ASEQ_Garbage_Collect_Prepare_Certificate( 
	    &(slot->prepare_certificate) );

}

util_stopwatch handle_proposal_sw;

void ASEQ_Handle_Proposal( signed_message *proposal ) {
    /* A Proposal was just generated. */
   
    //PRINT_Proposal(proposal);

    UTIL_Stopwatch_Stop( &handle_proposal_sw ); 
    Alarm(ASEQ_PRINT,"+++++++++++++++ HANDLE PROPOSAL %f\n",UTIL_Stopwatch_Elapsed(&handle_proposal_sw));
    UTIL_Stopwatch_Start( &handle_proposal_sw );

    if ( UTIL_I_Am_In_Leader_Site() ) {
        ASEQ_Update_ARU();  
 	if ( !UTIL_I_Am_Representative() ) { 
	  UTIL_Send_To_Server(proposal, VAR.My_Site_ID,
		    UTIL_Representative() );
	}
    }

    Alarm(DEBUG,"%d %d Handle Proposal %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID,
	    ((proposal_message*)(proposal+1))->seq_num );

    ASEQ_Process_Proposal( proposal );
}

/* Message Construction */

signed_message* ASEQ_Construct_Proposal( signed_message *pre_prepare ) {

    pre_prepare_message *pre_prepare_specific;
    signed_message *proposal;
    proposal_message *proposal_specific;
    signed_message *update;
    
    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);
    update = (signed_message*)(pre_prepare_specific+1);
    
    proposal = UTIL_New_Signed_Message();
    proposal_specific = (proposal_message*)(proposal+1);
    
    proposal->machine_id = 0;

    proposal->site_id = VAR.My_Site_ID;

    proposal->type = PROPOSAL_TYPE;

    proposal->len = sizeof(proposal_message) - sizeof(pre_prepare_message) +
	  pre_prepare->len;
    
    proposal_specific->local_view = pre_prepare_specific->local_view;
    
    proposal_specific->global_view = pre_prepare_specific->global_view;
    
    proposal_specific->seq_num = pre_prepare_specific->seq_num;

    Alarm(DEBUG,"%d %d %d\n",
	    proposal_specific->local_view,
	    proposal_specific->global_view,
	    proposal_specific->seq_num
	);
    
    /* Copy the update */
    memcpy( (void*)(proposal_specific+1), (void*)(update), 
	proposal->len - sizeof(proposal_message) );
    
    return proposal;
    
}

signed_message* ASEQ_Construct_Pre_Prepare( signed_message *mess, int32u seq_num ) {
    signed_message *pre_prepare;
    pre_prepare_message *pre_prepare_specific;
    int32u update_len;
    
    /* Construct new message */
    pre_prepare = UTIL_New_Signed_Message();

    pre_prepare_specific = (pre_prepare_message*)(pre_prepare + 1);
    
    /* Fill in the message based on the update. We construct a message that
     * contains the update by copying the update (which is a signed message)
     * into the Pre-Prepare message. */

    pre_prepare->site_id = VAR.My_Site_ID;
    
    pre_prepare->machine_id = VAR.My_Server_ID;
    
    pre_prepare->type = PRE_PREPARE_TYPE;

    update_len = mess->len + sizeof(signed_message);
    
    pre_prepare->len = update_len + sizeof(pre_prepare_message);

    pre_prepare_specific->seq_num = seq_num;          /* seq number */

#if 0
    // BYZ_CODE
    /* Skip a Global_seq -- this may cause prepare certificates and will cause
     * block and view change */
    if ( seq_num == 207 && 
	 VAR.My_Server_ID == 1 && 
	 VAR.My_Site_ID == 1 ) {
	//VAR.Global_seq = 208;
	pre_prepare_specific->seq_num = seq_num + 1;
    }
#endif

    pre_prepare_specific->local_view = PENDING.View;    /* the local view
							   number */

    pre_prepare_specific->global_view = GLOBAL.View;  /* the global view number
    */
    
    /* Now copy the body of the update to the pre prepare message */
    memcpy( (void*)(pre_prepare_specific + 1), 
	    (void*)mess, update_len );

    /* Sign the message with a standard RSA signature */
    UTIL_RSA_Sign_Message( pre_prepare );

    return pre_prepare;
    
}

signed_message* ASEQ_Construct_Prepare( signed_message *pre_prepare ) {

    signed_message *prepare; 
    prepare_message *prepare_specific;

    /* Construct new message */
    prepare = UTIL_New_Signed_Message();

    prepare_specific = (prepare_message*)(prepare + 1);
     
    prepare->site_id = VAR.My_Site_ID;
    
    prepare->machine_id = VAR.My_Server_ID;
    
    prepare->type = PREPARE_TYPE;

    prepare->len = sizeof(prepare_message);

    prepare_specific->seq_num = 
	((prepare_message*)(pre_prepare+1))->seq_num;  /* seq number */

    prepare_specific->local_view = PENDING.View;    /* the local view number */

    prepare_specific->global_view = GLOBAL.View;  /* the global view number */

    /* Now compute the digest of the update and copy it into the digest field */
    OPENSSL_RSA_Make_Digest( 
	    ((byte*)(pre_prepare + 1)) + sizeof(pre_prepare_message), 
	    pre_prepare->len - sizeof(pre_prepare_message), 
	    prepare_specific->update_digest );

    /* Compute a standard RSA signature. */
    UTIL_RSA_Sign_Message( prepare );

    return prepare;
 
}

int32u ASEQ_Update_ARU() {

    /* Attempt to update the aru */
    
    int32u prev_aru;
    int32u update;
    pending_slot_struct *slot;
    
    prev_aru = PENDING.ARU;
    
    update = 1;
    
    while ( update ) {
	slot = UTIL_Get_Pending_Slot_If_Exists( PENDING.ARU + 1 );
	if ( slot == NULL ) {
	    update = 0;
	} else if ( slot->proposal == NULL ) {
	    update = 0;
	} else /* there is a proposal in the slot */ {
	    PENDING.ARU++;
	    Alarm(ASEQ_PRINT, "Pending: %d; Global: %d\n", PENDING.ARU, GLOBAL.ARU);
	    ASEQ_Garbage_Collect_Pending_Slot( slot );
	}
    }

    Alarm(ASEQ_PRINT,"%d %d p.aru=%d gseq=%d p.max=%d g.aru=%d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, PENDING.ARU,
	    VAR.Global_seq, PENDING.Max_ordered, GLOBAL.ARU );

    if ( prev_aru == PENDING.ARU ) {
	return 0;
    } else {
	/* The aru has been updated */
	ASEQ_Process_Next_Update(); /* If there is room in window, inject update
	*/ 
	ASEQ_Process_Next_Proposal(); 
	LRECON_Do_Reconciliation();
	CCS_Response_Decider( PENDING_CONTEXT );
	CCS_Report_Decider( PENDING_CONTEXT );
	CCS_Union_Decider( PENDING_CONTEXT );
    }
    return 1;
    
}

void ASEQ_Reset_For_Pending_View_Change() {

    /* Clear things when a local view change occurs */

    /* Empty the update and proposal queues */
    UTIL_DLL_Clear(&update_dll);
    UTIL_DLL_Clear(&proposal_dll);
    
    /* Reset client pending timestamps */
    UTIL_CLIENT_Reset_On_View_Change();

}

/* Wrapper for retransmission */
void ASEQ_Retransmit(int dummy, void *dummyp ) {

    pending_slot_struct *slot;
    sp_time diff;
    sp_time now;

    /* FINAL */
    if ( GLOBAL.ARU > PENDING.ARU ) {
	PENDING.ARU = GLOBAL.ARU;
    }

    if ( UTIL_I_Am_Representative() && UTIL_I_Am_In_Leader_Site() ) {

	ASEQ_Process_Next_Update();

    	Alarm(ASEQ_PRINT, "ASEQ_Retransmit, global_seq = %d, GLOBAL.ARU = %d"
	       " PENDING.ARU = %d\n",
		VAR.Global_seq, GLOBAL.ARU, PENDING.ARU );

	/* pre_prepare retransmission for local progress */

	slot = UTIL_Get_Pending_Slot_If_Exists( PENDING.ARU + 1 );
	now = E_get_time();

	if ( slot != NULL ) {

	    diff = E_sub_time( now, slot->time_pre_prepare_sent );

	    if ( E_compare_time( diff, timeout_pre_prepare_retrans ) > 0 ) {
	    	/* retransmit pre_prepare */
		Alarm(DEBUG,"Pre prep Exp\n");
		if ( slot->pre_prepare != NULL ) {
		    slot->time_pre_prepare_sent = now;
		    Alarm(DEBUG,"Retrans pre_prepare_message %d\n",
			    ((pre_prepare_message*)(slot->pre_prepare+1))->seq_num);
		    UTIL_Site_Broadcast( slot->pre_prepare );
		} else if ( slot->prepare_certificate.pre_prepare != NULL ) {
		    slot->time_pre_prepare_sent = now;
		    Alarm(DEBUG,"Retrans prepare certificate" 
			  " pre_prepare_message %d\n", ((pre_prepare_message*)
			  (slot->prepare_certificate.pre_prepare+1))->seq_num);
		    UTIL_Site_Broadcast( slot->prepare_certificate.pre_prepare );
		}
	    }
	}

	/* Proposal retransmission -- for global progress */
	
	slot = UTIL_Get_Pending_Slot_If_Exists( GLOBAL.ARU + 1 );
	
	if ( slot != NULL ) {
	    
	    diff = E_sub_time( now, slot->time_proposal_sent );

	    if ( E_compare_time( diff, timeout_proposal_retrans ) > 0 ) {
	    	/* retransmit proposal */
		Alarm(DEBUG,"Pro Exp\n");
		if ( slot->proposal != NULL ) {
		    slot->time_proposal_sent = now;
		    Alarm(ASEQ_PRINT,"Retrans proposal_message %d\n",
			    ((proposal_message*)(slot->proposal+1))->seq_num);
		    UTIL_Send_To_Site_Representatives( slot->proposal );
		}
	    }

	}

    }
 
    E_queue( ASEQ_Retransmit, 0, NULL, timeout_pre_prepare_retrans );

}

void ASEQ_Initialize() {

    UTIL_DLL_Clear(&update_dll);
    UTIL_DLL_Clear(&proposal_dll);

    E_queue( ASEQ_Retransmit, 0, NULL, timeout_pre_prepare_retrans );

}

/* Response Window: Servers should not participate in ordering an update having
 * a sequence number that is higher than their either their pending or global
 * ARU by more than a certain amount. */
int32u ASEQ_Seq_Num_Within_My_Response_Window( int32u seq_num ) {

    if ( seq_num > PENDING.ARU + LOCAL_WINDOW + 1 ) {
	/* do not send if my pending aru is not high enough */
	Alarm(ASEQ_PRINT,"seq_num %d not in response window %d %d %d\n",
	      seq_num, PENDING.ARU, GLOBAL.ARU );
	return 0;
    }

    return 1;
}


#if 0

WAS IN Upon_Receiving_Prepare
    if ( slot->prepare_certificate.pre_prepare != NULL ) {
	/* There already is a prepare certificate, retransmit the signature share */
	if ( slot->sig_share[VAR.My_Server_ID] != NULL ) {
	    Alarm(DEBUG,"retran sig share for proposal\n");
	    UTIL_Site_Broadcast(
		slot->sig_share[VAR.My_Server_ID] );
	    return;
	}
    }

#endif


