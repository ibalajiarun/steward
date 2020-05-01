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

/* Local Representative Election Protocol.
 *
 * This protocol insures that a local representative will be elected.
 * 
 */
#include "data_structs.h"
#include "stdlib.h"
#include "rep_election.h"
#include "utility.h"
#include "apply.h"
#include "timeouts.h"
#include "construct_collective_state_protocol.h"
#include "construct_collective_state_util.h"
#include "threshold_sign.h"
#include "meta_globally_order.h"
#include "assign_sequence.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "global_view_change.h"

/* Global variables */
extern server_variables    VAR;
extern pending_data_struct PENDING;

/* Local functions */
signed_message* REP_Construct_L_New_Rep(void); 
signed_message* REP_Construct_Local_View_Proof(void);
void REP_Send_L_New_Rep(); 
void REP_Retransmit(int dummy, void *dummyp ); 
void REP_Send_Sig_Share_Local_View_Proof(); 
void REP_Send_Local_View_Proof_On_Wide_Area(); 

util_stopwatch Forward_proof_stopwatch[NUM_SITES+1];

void REP_Initialize() {
    /* Initialize the local representative election meta-protocol variables */

    int32u si;

    PENDING.View = 0; /* View 0 is defined to have preinstalled */
    
    PENDING.Is_preinstalled = 1; /* View 0 is preinstalled, a priori */
 
    /* Set all messages to NULL */
    for ( si = 0; si <= NUM_SERVERS_IN_SITE; si++ ) {
	PENDING.L_new_rep[ si ] = NULL;
	PENDING.Local_view_proof_share[ si ] = NULL;
    }

    for ( si = 0; si <= NUM_SITES; si++ ) {
	PENDING.Local_view_proof[ si ] = NULL;
	UTIL_Stopwatch_Start(
	    &(Forward_proof_stopwatch[si]) );
    }

}

int32u REP_Get_View_From_Proof(signed_message *local_proof) {
    if ( local_proof == NULL ) {
	return 0;
    }
    return ((local_view_proof_message*)(local_proof+1))->local_view;
}

void REP_Handle_Local_View_Proof_Message( signed_message *local_view_proof ) {
    /* Send the local view proof */

    Alarm(DEBUG,"%d %d Produced local view proof for view %d.\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, 
	    REP_Get_View_From_Proof(local_view_proof) );

    /* Send the local view proof on the wide area. */
    REP_Send_Local_View_Proof_On_Wide_Area();

    REP_Update_Preinstall_Status();

}


/* Send the local view proof on the wide area. */
void REP_Send_Local_View_Proof_On_Wide_Area() {
   
    /* We send our own local view proof to all other servers. */

    signed_message *lv_proof; 
	
    lv_proof = PENDING.Local_view_proof[VAR.My_Site_ID];

    Alarm(DEBUG,"lv_proof %d\n",lv_proof);

    UTIL_Send_To_Site_Servers_With_My_ID(lv_proof); 
}

int32u REP_Get_Suggested_View( signed_message *mess ) {
    if (mess == NULL) return 0;
    return ((l_new_rep_message*)(mess+1))->view;
}

static int REP_cmp_l_new_rep( const void *i1, const void *i2 ) {
    int32u v1, v2;

    v1 = REP_Get_Suggested_View(*(signed_message**)(i1));
    v2 = REP_Get_Suggested_View(*(signed_message**)(i2));

    if ( v1 < v2 ) return -1;
    if ( v1 > v2 ) return 1;
    return 0;

}

int32u REP_Preinstall_Proof_View_From_Proof_Message() {

    /* From my current Local_view_proof message, get the view. */

    int32u view;

    view = REP_Get_View_From_Proof( 
	    PENDING.Local_view_proof[VAR.My_Site_ID] );

    return view;

}

int32u REP_Preinstall_Proof_View() { 

    int32u v1;
    int32u v2;

    v1 = REP_Preinstall_Proof_View_From_Proof_Message(); 
    v2 = REP_Preinstall_Proof_View_From_L_New_Rep(); 

    if ( v1 > v2 ) return v1;
    return v2;

}

int32u REP_Preinstall_Proof_View_From_L_New_Rep() {
    /* From the new_l_rep messages, determine the maximum view which
     * preinstalled. We assume that these new_l_rep messages are valid. */

    signed_message *sorted[NUM_SERVER_SLOTS];
    int32u si;
    int32u mcount;
    
    mcount = 0;
    
    /* Copy */
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	sorted[si-1] = PENDING.L_new_rep[si];
	if ( sorted[si-1] != NULL ) {
	    mcount++;
	}
    }

    Alarm(DEBUG,"L_new_rep messages %d\n",mcount);
    
    /* Sort the array */
    qsort( sorted, NUM_SERVERS_IN_SITE, sizeof(signed_message*), 
           REP_cmp_l_new_rep );
   
    /* We have 2f+1 l_new_rep messages with views higher or equal to the f+1 in
     * the sorted array. */
    /* REMEMBER: This is zero based, so the index takes this into account */

    return REP_Get_Suggested_View(sorted[VAR.Faults]);
   

}

void REP_Update_Preinstall_Status() {

    /* Has the current view preinstalled? If so, make sure that the
     * preinstalled flag is set to 1. */

    int32u pview;
    signed_message *l_new_rep;

    pview = REP_Preinstall_Proof_View(); 

    if ( pview >= PENDING.View ) {
	Alarm(DEBUG,"PREINSTALLED\n");
	if ( !PENDING.Is_preinstalled ) {
	    GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change();
	    REP_Send_L_New_Rep();
	}
	PENDING.Is_preinstalled = 1;
	if ( pview > PENDING.View ) {
	    PENDING.View = pview;
	    Alarm(PRINT, "Local view jump: %d\n", 
	          PENDING.View );
	    /* Changed pending view, so we need to reset ccs prending context.
	     * */
	    GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change();
	    ASEQ_Reset_For_Pending_View_Change();
	    CCS_Reset_Data_Structures(PENDING_CONTEXT);
	    CCS_Reset_Data_Structures( GLOBAL_CONTEXT );
	    /* Send a new L_New_Rep Message */
	    /* Construct a l_new_rep message */
	    l_new_rep = REP_Construct_L_New_Rep();
	    /* Apply this message to the data structures */
	    APPLY_Message_To_Data_Structs( l_new_rep );
	    REP_Send_L_New_Rep();
 	}
	if ( UTIL_I_Am_Representative() ) {
	    CCS_Send_Invocation_Message( PENDING_CONTEXT,
	            UTIL_Get_ARU( PENDING_CONTEXT ) );
	    if ( UTIL_I_Am_In_Leader_Site() ) {
		CCS_Send_Invocation_Message( GLOBAL_CONTEXT,
		    UTIL_Get_ARU(GLOBAL_CONTEXT) );
	    }
	}   
	/* If I have already made the sig_share, I should resend it
	 * without making it again. I do not need to send it if pview is based
	 * on the proof message. */
	if ( pview > REP_Preinstall_Proof_View_From_Proof_Message() ) {
	   REP_Send_Sig_Share_Local_View_Proof();
	} 
    }

}

void REP_Suggest_New_Local_Representative() {

    int32u preinstalled_view;
    signed_message *l_new_rep;
    
    /* If I have not preinstalled my current view, then I must not increment my
     * view. */
    
    preinstalled_view = REP_Preinstall_Proof_View(); 
     
    if ( preinstalled_view < PENDING.View ) {
	return;
    }

    PENDING.Is_preinstalled = 0;
   
    PENDING.View++;

    /* Clear the CCS Data Structures */
    CCS_Reset_Data_Structures( PENDING_CONTEXT );
    CCS_Reset_Data_Structures( GLOBAL_CONTEXT );
    GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change();
    ASEQ_Reset_For_Pending_View_Change(); 
 
    Alarm(PRINT,"Suggest new local view: %d\n"
	    , PENDING.View); 

    /* Construct a l_new_rep message */
    l_new_rep = REP_Construct_L_New_Rep();

    /* Apply this message to the data structures */
    APPLY_Message_To_Data_Structs( l_new_rep );
 
    REP_Send_L_New_Rep();
     
    /* Enqueue retransmission */
    E_queue( REP_Retransmit, 0, NULL, timeout_l_new_rep_retrans );

}

void REP_Print_Status() {

    if ( NUM_SERVERS_IN_SITE == 4 ) {

	/* A simple print for proof of view and the claimed views */

        Alarm(PRINT,"Proof view %d. "
	    "Servers report: s1=%d s2=%d s3=%d s4=%d\n", 
	    REP_Preinstall_Proof_View_From_L_New_Rep(),
	    REP_Get_Suggested_View( PENDING.L_new_rep[1]),
	    REP_Get_Suggested_View( PENDING.L_new_rep[2]),
	    REP_Get_Suggested_View( PENDING.L_new_rep[3]),
	    REP_Get_Suggested_View( PENDING.L_new_rep[4])
	       	);
    }
 
}    

/* Wrapper for retransmission */
void REP_Retransmit(int dummy, void *dummyp ) {
    /*REP_Print_Status();*/
    REP_Send_L_New_Rep(); 
    E_queue( REP_Retransmit, 0, NULL, timeout_l_new_rep_retrans );
}

/* Send the highest proof that I have -- this may be a set of L_New_Rep
 * messages OR a threshold signed local view proof message. */
void REP_Send_Local_View_Proof_On_Local_Area() {

    int32u si;
    signed_message *l_new_rep;
    int32u p_v;
    int32u nr_v;
    int32u num_sent;

    p_v = REP_Preinstall_Proof_View_From_Proof_Message(); 
    nr_v = REP_Preinstall_Proof_View_From_L_New_Rep(); 

    /* Send my l_new_rep message to all servers in the site */
    UTIL_Site_Broadcast( PENDING.L_new_rep[VAR.My_Server_ID] );
 
    if ( p_v >= nr_v ) { 
	/* Send the single local_view_proof message */
	if ( PENDING.Local_view_proof[VAR.My_Server_ID] != NULL ) {
	    /* We may not have the signed message yet. */
	    UTIL_Site_Broadcast( PENDING.Local_view_proof[VAR.My_Server_ID] );
	    return;
	}
    } 
    /* otherwise, send the set of l_new_rep messages that prove nr_v */
    num_sent = 0;
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	l_new_rep = PENDING.L_new_rep[si];
	if ( l_new_rep != NULL &&
	    REP_Get_Suggested_View(l_new_rep) >= nr_v ) {
	    /* Send the l_new_rep message */
	    UTIL_Site_Broadcast( PENDING.L_new_rep[si] );
	    num_sent++;
	    if ( num_sent == 2 * VAR.Faults + 1 ) {
		/* Stop sending */
		si = NUM_SERVERS_IN_SITE + 1;
	    }
	}
    }
 

}

void REP_Print_Site_Reps() {

    int32u si;

    for ( si = 1; si <= NUM_SITES; si++ ) {
	Alarm(PRINT,"%d %d Site rep of site %d is %d, lv_proof %d.\n",
	    VAR.My_Site_ID,VAR.My_Server_ID,si,
	    UTIL_Get_Site_Representative(si),
	    REP_Preinstall_Proof_View() );
    }
    
}


/* Send my L_New_Rep and proof that the previous view installed. */
void REP_Send_L_New_Rep() {

    int32u con;

    /* Send my l_new_rep message to all servers in the site */
    UTIL_Site_Broadcast( PENDING.L_new_rep[VAR.My_Server_ID] );

    /* Send the latest proof on the local area. */
    REP_Send_Local_View_Proof_On_Local_Area();

    /* Print a status message */
    /* REP_Print_Site_Reps(); */

    if ( !GLOBO_Is_Progress_Being_Made_For_Local_View_Change() ) {
	REP_Suggest_New_Local_Representative();
    }	
    if ( !GLOBO_Is_Progress_Being_Made_For_Global_View_Change() ) {
	GVC_Suggest_New_Global_View(); 
    }

    for ( con = 0; con <= 1; con++ ) {	
       CCS_Response_Decider(con);
       CCS_Report_Decider(con);
       CCS_Union_Decider(con);
    }

}

/* Handle messages, if necessary. */
void REP_Process_Message( signed_message *mess ) {

    if ( mess->type == SITE_LOCAL_VIEW_PROOF_TYPE ) {
	/* We should site broadcast any messages that come from a server
	 * outside of our site. */
	if ( mess->site_id != VAR.My_Site_ID ) {
	    /* Forward */
	    /* If I haven't forwarded a message for a while, then forward it.
	     * */
	    UTIL_Stopwatch_Stop(
		    &(Forward_proof_stopwatch[mess->site_id]) );
	    if ( UTIL_Stopwatch_Elapsed( 
		    &(Forward_proof_stopwatch[mess->site_id]))
	         > 0.5 ) {
		UTIL_Stopwatch_Start(
		    &(Forward_proof_stopwatch[mess->site_id]) );
		UTIL_Site_Broadcast( mess );
	    }	
	}
	
    }

    

}

/* Make a new l_new_rep message */
signed_message* REP_Construct_L_New_Rep() {
    
    signed_message *l_new_rep;
    
    /* make a new message */
    l_new_rep = UTIL_New_Signed_Message(); 
    
    /* assign the view */
    ((l_new_rep_message*)(l_new_rep + 1))->view = PENDING.View;

    /* put in the length */
    l_new_rep->len = sizeof(l_new_rep_message);

    /* type */
    l_new_rep->type = L_NEW_REP_TYPE;

    /* site id */
    l_new_rep->site_id = VAR.My_Site_ID;

    /* machine id */
    l_new_rep->machine_id = VAR.My_Server_ID;
    
    /* Sign the message */
    UTIL_RSA_Sign_Message( l_new_rep );

    return l_new_rep;
    
}

/* When the server preinstalls a new local view, it must send a signature share
 * message so that a threshold signed message can be sent that contains the
 * local view of this site. */
void REP_Send_Sig_Share_Local_View_Proof() {

    signed_message *local_view_proof;

    /* If we have already made the signature share, then do a site broadcast on
     * this share. */
    local_view_proof = REP_Construct_Local_View_Proof();

    /* Invoke THRESH on the contructed message. */
    THRESH_Invoke_Threshold_Signature( local_view_proof );

    dec_ref_cnt( local_view_proof );
}

signed_message* REP_Construct_Local_View_Proof() {

    signed_message *local_view_proof;
    
    /* make a new message */
    local_view_proof = UTIL_New_Signed_Message(); 
    
    /* assign the view */
    ((local_view_proof_message*)(local_view_proof + 1))->local_view = 
	REP_Preinstall_Proof_View();

    /* put in the length */
    local_view_proof->len = sizeof(local_view_proof_message);

    /* type */
    local_view_proof->type = SITE_LOCAL_VIEW_PROOF_TYPE;

    /* site id */
    local_view_proof->site_id = VAR.My_Site_ID;

    /* machine id */
    local_view_proof->machine_id = 0;

    /* NOTE: This is a signature share message so we don't sign it. This is
     * done in the threshold_sign code. */

    return local_view_proof;

}

