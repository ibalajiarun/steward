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

#include "meta_globally_order.h"
#include "threshold_sign.h"
#include "utility.h"
#include "timeouts.h"
#include "ordered_receiver.h"
#include "local_reconciliation.h"
#include "global_reconciliation.h"
#include "util/alarm.h"
#include "util/memory.h"
#include "assign_sequence.h"
#include "construct_collective_state_protocol.h"
#include <stdlib.h>

extern server_variables VAR;
extern global_data_struct GLOBAL;
extern pending_data_struct PENDING;

util_stopwatch stopwatch;

signed_message* GLOBO_Construct_Accept( signed_message *proposal ); 
int32u GLOBO_Update_ARU(); 

util_stopwatch global_progress_stopwatch;

/* Local functions */
void GLOBO_Dump_Test_Results( double updates_per_sec ); 

void GLOBO_Dispatcher( signed_message *mess ) {

    switch ( mess->type ) {
	case PROPOSAL_TYPE:
	    GLOBO_Process_Proposal(mess);
	    return;
	case ACCEPT_TYPE:
	    return;
    }

}

void GLOBO_Initialize() {

    GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change();

}

void GLOBO_Emulate_Send_Accept( int dummy, void *proposal ) {
    signed_message *accept;

    accept = GLOBO_Construct_Accept( (signed_message*)proposal );
    UTIL_Busy_Wait(0.009);
    UTIL_Send_To_Site_Representatives( accept );
    dec_ref_cnt( accept );
}

int32u GLOBO_Within_Response_Window(int32u seq_num) {

  /* FINAL added plus 10 */
    if (seq_num > GLOBAL.ARU + GLOBAL_WINDOW + 10) {
      Alarm(GLO_PRINT, "***Not Responding, garu = %d, seq = %d\n", 
	    GLOBAL.ARU, seq_num);
	return 0;
    }

    return 1;

}

void GLOBO_Forward_Proposal( signed_message *pro ) {

    proposal_message *pro_specific;
    proposal_message *old_pro_specific;
    global_slot_struct *slot;

    if ( !UTIL_I_Am_Representative() ) {
	return;
    }

    pro_specific = (proposal_message*)(pro+1);

    slot = UTIL_Get_Global_Slot_If_Exists( pro_specific->seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( slot->proposal == NULL ) {
	return;
    }

    old_pro_specific = (proposal_message*)(slot->proposal+1);

    UTIL_Stopwatch_Stop(&slot->forward_proposal_stopwatch);

    if ( UTIL_Stopwatch_Elapsed(&slot->forward_proposal_stopwatch) < 
	    0.020 ) {
	/* I forwarded it recently. */
	return;	
    }

    UTIL_Stopwatch_Start(&slot->forward_proposal_stopwatch);
    UTIL_Site_Broadcast( pro );

}


void GLOBO_Process_Proposal( signed_message *proposal ) {

   /* Take a proposal that is valid, generate an Accept, and send a sig share
    * for the Accept. */

    signed_message *accept;
    proposal_message *proposal_specific;
    proposal_message *old_proposal_specific;
    global_slot_struct *slot; 
    sp_time now;
    sp_time diff;
    signed_message *ordered_proof;

    proposal_specific = (proposal_message*)(proposal+1);

    Alarm(DEBUG,"%d %d GLOBO_Process_Proposal %d\n",
	    VAR.My_Site_ID,VAR.My_Server_ID, proposal_specific->seq_num ); 


    if ( proposal_specific->global_view != GLOBAL.View ) {
	/* Conflict lets this through so that, if necessary, the proposal can
	 * be applied and forwarded */
	
	/* We forward the proposal if it has a view that is equal to the view
	 * that I currently have (because I already applied this proposal) */
	slot = UTIL_Get_Global_Slot_If_Exists( proposal_specific->seq_num );
	if ( slot != NULL ) {
	    if(slot->proposal == NULL)
	       return;

	    old_proposal_specific = (proposal_message*)(slot->proposal+1);
	    if ( proposal_specific->global_view >=
		    old_proposal_specific->global_view ) {
	      GLOBO_Forward_Proposal( proposal );
	    }
	}
	return;
    }

    /* THIS FUNCTION ASSUMES THAT: the proposal has my global view */
    UTIL_Purge_Global_Slot( proposal ); 

    if ( UTIL_I_Am_In_Leader_Site() ) {
	/* JWL SPEED */
	/* don't make a proposal if we are in the leader site */
	return;
    }

    if ( !GLOBO_Within_Response_Window(proposal_specific->seq_num) ) {
	/* We CANNOT respond to the proposal if it is too far ahead of our
	 * global aru!! */
	Alarm(GLO_PRINT,"GLOBO_Process_Proposal -- Not in response window\n");
	/* Send the proposal to everyone in my site */
	GLOBO_Forward_Proposal( proposal ); 
	return;
    }

    slot = UTIL_Get_Global_Slot(proposal_specific->seq_num);

    /* Global Retransmission Logic */
    if ( slot->is_ordered ) {
	/* Already ordered */
	ordered_proof = 
	  GRECON_Construct_Ordered_Proof_Message( proposal_specific->seq_num);
	UTIL_Send_To_Site_Representatives( ordered_proof );
	return;
    }

    if ( slot->accept[VAR.My_Site_ID] != NULL ) {
	/* Put a minimum retrans time here */
	Alarm( GLO_PRINT,"Retrans my accept: seq %d\n",
	       proposal_specific->seq_num);
	if ( GLOBAL.View != 
	     ((accept_message*)(slot->accept[VAR.My_Site_ID] + 1))
	     ->global_view ) {
	    Alarm(GLO_PRINT,"RETRANS PRO WITH VIEW OTHER THAN MINE %d %d\n",
		GLOBAL.View,	    
		((accept_message*)(slot->accept[VAR.My_Site_ID] + 1))->global_view );
	}
	UTIL_Send_To_Site_Representatives( slot->accept[VAR.My_Site_ID] );
	return;
    }

#if EMULATE_NON_REP_SITE
    /* Send an accept after a busy wait -- Note, this is intended only for
     * benchmarking, and therefore IT IS NOT attack resilient */
    if ( UTIL_I_Am_In_Leader_Site() ) {
	return;
    }
    if ( UTIL_I_Am_Representative() ) {
	/* Send an accept message */
	E_queue( GLOBO_Emulate_Send_Accept, 
		 0, proposal, timeout_zero );
    }
    return;
#endif
  
    /* Local Retransmission Logic */
    if ( slot->accept_share[VAR.My_Server_ID] != NULL ) {
	/* if I haven't sent my accept_share or my proposal for some amount of
	 * time, then resend them */
	now = E_get_time();
	diff = E_sub_time(now,slot->time_accept_share_sent);
	if ( E_compare_time(diff,timeout_accept_share_minimum_retrans) > 0 ) {
	    UTIL_Site_Broadcast( slot->accept_share[VAR.My_Server_ID] );
	    slot->time_accept_share_sent = now;
	    if ( UTIL_I_Am_Representative() ) {
		UTIL_Site_Broadcast( proposal );
	    }
	}
	return;
    }

    if ( proposal_specific->global_view != GLOBAL.View ) {
	/* Already handled in conflict */
	return;
    }

    accept = GLOBO_Construct_Accept( proposal );

    /* Send a sig share for the proposal */
    Alarm(DEBUG,"%d %d Invoke THRESH On Accept\n", VAR.My_Site_ID, VAR.My_Server_ID
	    );
    /* didn't submit share yet */

    /* Send the proposal to everyone in my site */
    GLOBO_Forward_Proposal( proposal ); 
	
    Alarm(DEBUG,"%d %d Site Broadcast Proposal: seq %d\n",
	   VAR.My_Site_ID, VAR.My_Server_ID, 
	   ((proposal_message*)(proposal+1))->seq_num);

    now = E_get_time();
    slot->time_accept_share_sent = now;

    UTIL_Update_CCS_STATE_GLOBAL( ((accept_message*)(accept+1))->seq_num );

    Alarm(GLO_PRINT,"Sending share for accept seq %d\n",
	    ((accept_message*)(accept+1))->seq_num );

    THRESH_Invoke_Threshold_Signature( accept );
    dec_ref_cnt(accept);

    if ( VAR.My_Site_ID == 2 ) {
	Alarm(DEBUG,"GLOBO_Process_Proposal\n");
    }

}

/* Message Construction */
signed_message* GLOBO_Construct_Accept( signed_message *proposal ) {

    signed_message *accept;
    proposal_message *proposal_specific;
    accept_message *accept_specific;   
 
    proposal_specific = (proposal_message*)(proposal+1);
    
    accept = UTIL_New_Signed_Message();
    accept_specific = (accept_message*)(accept+1);
    
    accept->machine_id = 0;

    accept->site_id = VAR.My_Site_ID;

    accept->type = ACCEPT_TYPE;

    accept->len = sizeof(accept_message);
    
    accept_specific->global_view = proposal_specific->global_view;
    
    accept_specific->seq_num = proposal_specific->seq_num;

    Alarm(DEBUG,"%d %d\n",
	    accept_specific->global_view,
	    accept_specific->seq_num
	);
    
    return accept;
 
}

void GLOBO_Handle_Accept( signed_message *accept ) {
 
    accept_message *accept_specific;
 
    accept_specific = (accept_message*)(accept+1);

    if ( UTIL_I_Am_Representative() ) {
	Alarm(GLO_PRINT,"%d %d GLOBO_Handle_Accept s%d sit%d gv%d\n",
		VAR.My_Site_ID, VAR.My_Server_ID, accept_specific->seq_num, 
		accept->site_id, GLOBAL.View );
	UTIL_Send_To_Site_Representatives( accept );
    }

}

void GLOBO_Handle_Global_Ordering( global_slot_struct *slot) {

    signed_message *proposal;
    proposal_message *proposal_specific;
    signed_message *update;
    update_message *update_specific;

    double elapsed;

    Alarm(GLO_PRINT,"GLOBO_Handle_Global_Ordering\n");

    if ( slot->is_ordered ) {
	return;
    }

    slot->is_ordered = 1;

    proposal = slot->proposal;
    proposal_specific = (proposal_message*)(proposal+1);

    /* Update the client data structure if necessary with timestamp
     * and sequence number information.*/
    UTIL_CLIENT_Process_Globally_Ordered_Proposal(proposal);

    /* Keep track of the maximum ordered value */
    if ( proposal_specific->seq_num > GLOBAL.Max_ordered ) {
	GLOBAL.Max_ordered = proposal_specific->seq_num;
    }

    GLOBO_Update_ARU();
    
    if ( GLOBAL.ARU < GLOBAL.Max_ordered ) {
	GRECON_Start_Reconciliation( GLOBAL.Max_ordered );
    }

    CCS_Union_Decider( GLOBAL_CONTEXT );     

    update = (signed_message*)(proposal_specific+1);
    update_specific = (update_message*)(update+1);

    if ( proposal_specific->seq_num % 1000 == 1 && 
	 proposal_specific->seq_num == 2001 ) {
	Alarm(GLO_PRINT,"%d %d recv: %d global_aru: %d\n", 
	   VAR.My_Site_ID , VAR.My_Server_ID,
	   proposal_specific->seq_num, GLOBAL.ARU );
#if STATE_MACHINE_OUTPUT 
	//fflush(0);
#endif
	UTIL_Dump_Mess_Count();
    }
 
    if ( proposal_specific->seq_num > GLOBAL.Max_ordered ) {
	/* Do local reconciliation */
	LRECON_Do_Reconciliation();
    }

    UTIL_CLIENT_Respond_To_Client(update, proposal_specific->seq_num);

    /* JUST PRINT SOME RESULTS IF I AM REP at LEADER SITE */
    if ( !UTIL_I_Am_Representative() || !UTIL_I_Am_In_Leader_Site() ) {
	return;
    }

    elapsed = 0;
#if 0

    /* BENCHMARK */

    if ( proposal_specific->seq_num % 1000 == 1 ) {
	if ( proposal_specific->seq_num > 1 ) {
	    UTIL_Stopwatch_Stop( &stopwatch );
	    elapsed = UTIL_Stopwatch_Elapsed( &stopwatch ); 
	    /* Print the run to a data file */
	    if ( proposal_specific->seq_num == 2001 ) {
		Alarm(PRINT,"Update: %d Elapsed_Time: %f mess/sec: %f"
			    " num_cli = %d\n",
		      proposal_specific->seq_num, elapsed, 1000.0 / elapsed,
		      UTIL_Number_Of_Clients_Seen() );
		GLOBO_Dump_Test_Results( 1000.0 / elapsed );
	    }		
	}
	UTIL_Stopwatch_Start( &stopwatch );
    }
#endif

}


void GLOBO_Dump_Test_Results( double updates_per_sec ) {

    /* Create a test file name, open it, write the results, and exit */


#if SERVER_OUTPUT_THROUGHPUT

    char fname[1000];
    int32u num_c;
    FILE *f;

    num_c = UTIL_Number_Of_Clients_Seen(); 

    sprintf(fname,"run_dat.%02d.dat", num_c);
   
    f = fopen(fname,"w");
    
    fprintf(f,"%d %f\n", num_c, updates_per_sec);

    fflush(f);

#endif

    exit(1);

}

void GLOBO_Garbage_Collect_Global_Slot( global_slot_struct *slot ) {

    int32u si;
    signed_message *m;

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	m = slot->accept_share[si];
	if ( m != NULL ) {
	    dec_ref_cnt(m);
	}
    }

}

int32u GLOBO_Update_ARU() {

    /* Attempt to update the aru */
 
    int32u prev_aru;
    int32u update;
    global_slot_struct *slot;
 
    prev_aru = GLOBAL.ARU;
 
    update = 1;
 
    while ( update ) {
	slot = UTIL_Get_Global_Slot_If_Exists( GLOBAL.ARU + 1 );
	if ( slot == NULL ) {
	    update = 0;
	} else if ( !slot->is_ordered ) {
	    update = 0;
	} else /* it is globally ordered */ {
	    /* slot is ordered... */
	    /* FINAL -- added the following line, move it from handle globally
	     * ordering */
	    //UTIL_CLIENT_Process_Globally_Ordered_Proposal(slot->proposal);
	    UTIL_Apply_Update_To_State_Machine( slot->proposal );
	    GLOBO_Garbage_Collect_Global_Slot(slot);
	    GLOBAL.ARU++;
	}
    }
    
    Alarm(GLO_PRINT,"%d %d glob ordered g.aru=%d gseq=%d "
	    "g.max=%d p.aru=%d p.max=%d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, GLOBAL.ARU, 
	    VAR.Global_seq, GLOBAL.Max_ordered, PENDING.ARU, 
	    PENDING.Max_ordered );

    if ( prev_aru != GLOBAL.ARU && 
        GLOBAL.Max_ordered > GLOBAL.ARU ) {
        LRECON_Do_Reconciliation();
	GRECON_Start_Reconciliation( GLOBAL.Max_ordered );
    }

    if ( prev_aru != GLOBAL.ARU ) {
   	GRECON_Send_Request();
	CCS_Global_Response_Decider(); 
    }

    if ( prev_aru == GLOBAL.ARU ) {
	return 0;
    }


    if ( UTIL_I_Am_In_Leader_Site() && UTIL_I_Am_Representative() ) {
	Alarm(PRINT,"\n");
    } else if ( GLOBAL.ARU % 20 == 0 ) {
	Alarm(PRINT,"\n");
    }

    GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change();
    CCS_Response_Decider( GLOBAL_CONTEXT );
    CCS_Report_Decider( GLOBAL_CONTEXT );
    CCS_Union_Decider( GLOBAL_CONTEXT );

    /* I may need to send another proposal */
    if ( UTIL_I_Am_Representative() && UTIL_I_Am_In_Leader_Site() ) {
	ASEQ_Process_Next_Update();
	ASEQ_Process_Next_Proposal(); 
    }

    return 1;

}

void GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change() {

    UTIL_Stopwatch_Start( &global_progress_stopwatch );

}

void GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change() {

    GLOBAL.maximum_pending_view_when_progress_occured = PENDING.View; 
    GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change();

}

int32u GLOBO_Is_Progress_Being_Made_For_Local_View_Change() {

    double timeout;

    /* Check for minimum global rate, minimum time since last update, etc */

    /* I must have updated my global aru within some amount of time. */
    timeout = 3.0;

    if ( UTIL_I_Am_In_Leader_Site() ) {
	timeout = timeout * 2;
    }

    UTIL_Stopwatch_Stop( &global_progress_stopwatch );


    if ( UTIL_Stopwatch_Elapsed( &global_progress_stopwatch ) > timeout ) {
	return 0;
    }
    
    return 1;

}

int32u GLOBO_Is_Progress_Being_Made_For_Global_View_Change() {

    int32u mark;

/* FINAL we were not adjusting mark before this change */

    mark = NUM_SERVERS_IN_SITE; 

    if ( !UTIL_I_Am_In_Leader_Site() ) {
	mark = mark * 2;
    }

    if ( PENDING.View - 
	 GLOBAL.maximum_pending_view_when_progress_occured >
	    mark ) {
	return 0;
    }	

    return 1;

}


