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

#include "global_view_change.h"
#include "data_structs.h"
#include "stdlib.h"
#include "rep_election.h"
#include "utility.h"
#include "apply.h"
#include "timeouts.h"
#include "construct_collective_state_protocol.h"
#include "construct_collective_state_util.h"
#include "threshold_sign.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "meta_globally_order.h"

/* Protocol GVC -- This protocol produces a threshold signed message that
 * proves that the site is trying to preinstall a new global view number. */

/* We store 1 message for each site. These are threshold signed.  type
 * SITE_GLOBAL_VIEW_CHANGE_TYPE */

/* We also store 1 sig share message for each server in the site for the
 * SITE_GLOBAL_VIEW_CHANGE message. This is stored by the apply code. */

/* Global Variables */
extern server_variables VAR;

extern global_data_struct GLOBAL;

extern pending_data_struct PENDING;


/* Local Functions */
signed_message* Construct_Global_View_Change_Message(); 
int32u GVC_Global_Preinstall_Proof_View(); 
int32u GVC_Count_VC_Messages_In_VC_Array( int32u target_view ); 
int32u GVC_Maximum_View_In_Global_VC_Array(); 
void GVC_Send_Proof( int32 dummy, void *dummyp ); 
void GVC_Send_Proof_To_All_Servers(); 

/* Get the view */
int32u GVC_Get_View( signed_message *global_view_change ); 
int32u GVC_Get_View_By_Site_ID( int32u site_id );

int32u My_old_global_view_proof;

util_stopwatch Forward_gvc_stopwatch[NUM_SITES+1];

/* Get the view number of the threshold signed global view change message sent
 * by the specified site */
int32u GVC_Get_View_By_Site_ID( int32u site_id ) {

    return GVC_Get_View(GLOBAL.Global_VC[site_id]); 

}

int32u GVC_Get_View( signed_message *global_vc ) {
    
    global_view_change_message *gv_specific;
    
    /* Get the view change message for the specified site_id */
    if ( global_vc == NULL ) {
	/* If there is nothing there, then the view is defined to be zero. */
	return 0; 
    }

    gv_specific = (global_view_change_message*)(global_vc+1);

    /* otherwise */
    return gv_specific->global_view; 

}

/* Get the maximum view in our stored array of global_view_change_message's */
int32u GVC_Maximum_View_In_Global_VC_Array() {

    int32u si;
    int32u maxv, this_view;

    maxv = 0;
    for ( si = 1; si <= NUM_SITES; si++ ) {
	this_view = GVC_Get_View_By_Site_ID( si );
	if ( this_view > maxv ) {
	    maxv = this_view;
	}
    }

    return maxv;

}

/* Count the number of global_view_change_message's that we have which have the
 * specified target view. */
int32u GVC_Count_VC_Messages_In_VC_Array( int32u target_view ) {

    int32u count;
    int32u si;

    count = 0;
    for ( si = 1; si <= NUM_SITES; si++ ) {
	if ( GVC_Get_View_By_Site_ID(si) == target_view ) {
	    count++;
	}
    }
    
    return count;

}

/* Return the global view number which I have proof preinstalled. */
int32u GVC_Global_Preinstall_Proof_View() {

    /* The view that I have proof preinstalled. This is based on the threshold
     * signed messages from other sites. These are trusted messages -- each one
     * represents a global view number which the site agreed upon. */

    int32u maxv;
    int32u count1, count2;

    /* Get the maximum global view in the GLOBAL.Global_vc array. */
    maxv = GVC_Maximum_View_In_Global_VC_Array();

    /* We should have proof that either maxv preinstalled OR that maxv - 1
     * preinstalled. We must check to see which is the case. */
 
    /* Count the number of maxv */
    count1 = GVC_Count_VC_Messages_In_VC_Array( maxv );
    
    if ( count1 >= (NUM_SITES / 2) + 1 ) {
	/* There is a majority of global_view_change mesages with the maximum
	 * view. Therefore, we have proof that the maximum view preinstalled.
	 * */
	 return maxv;
    } 
    
    /* Check that we have proof that the maximum view - 1 preinstalled. */
    count2 = GVC_Count_VC_Messages_In_VC_Array( maxv - 1 );
    if ( count1 + count2 >= (NUM_SITES / 2) + 1 ) {
	return maxv - 1;
    }
    
    /* We should never reach this point. */
    Alarm(DEBUG,"***** WARNING ********\n"
	  "%d %d ******* GVC_Global_Preinstall_Proof_View()\n",
	  VAR.My_Site_ID, VAR.My_Server_ID );

    return 0;

}

void GVC_Increase_Global_View( int32u new_view ) {

    /* THIS IS THE ONLY PLACE WHERE GLOBAL.View IS INCREASED */
    int32u preinstalled_view;
    int32u send_sig_share; 
    signed_message *gvc;

    send_sig_share = 0;

    if ( new_view < GLOBAL.View ) {
	return;
    }

    if ( new_view > GLOBAL.View ) {
	send_sig_share = 1;
	GLOBAL.View = new_view;
	GLOBAL.Is_preinstalled = 0;
	GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change();
#if 0
	CCS_Reset_Data_Structures( GLOBAL_CONTEXT );
#endif
    }
    
    preinstalled_view = GVC_Global_Preinstall_Proof_View();
     
    if ( !GLOBAL.Is_preinstalled ) {
	if ( preinstalled_view == GLOBAL.View ) {
	    /* The global view is preinstalled because we have proof */
	    GLOBAL.Is_preinstalled = 1;
	    /* RESET Global Progress Bookkeeping */
	    GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change();
#if 0
	    CCS_Reset_Data_Structures( GLOBAL_CONTEXT );
	    if ( UTIL_I_Am_Representative() ) {
		CCS_Send_Invocation_Message( GLOBAL_CONTEXT,
		    UTIL_Get_ARU(GLOBAL_CONTEXT) );
	    }
#endif
	}
    }

    if ( send_sig_share ) {
	gvc = Construct_Global_View_Change_Message();
	THRESH_Invoke_Threshold_Signature( gvc );
	dec_ref_cnt( gvc );
    }

}

/* Invoke a THRESH theshold sig for a new GVC_SITE_G_VIEW_ATTEMPT */
void GVC_Suggest_New_Global_View() {
    
    /* Send a share for a new global_view_change_message. */

    int32u preinstalled_view;

    /* If I have not preinstalled my current view, then I must not increment my
     * view. */
    
    preinstalled_view = GVC_Global_Preinstall_Proof_View(); 
   
    if ( preinstalled_view < GLOBAL.View ) {
	Alarm(DEBUG,"RET\n");
	return;
    }

    /* Now increment my global view */
    GVC_Increase_Global_View( GLOBAL.View + 1 );

    Alarm(PRINT,"Suggest new global view: %d\n",
	    GLOBAL.View
	    );


}

void GVC_Handle_Global_View_Change_Message( signed_message *gvc ) {

    /* We get a global view change message back after its been combined. */

    /* Send it to the the servers in the other sites. */

    Alarm(DEBUG,"%d %d GVC_Handle_Global_View_Change_Message: v = %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, GVC_Get_View(gvc) );

    GVC_Send_Proof_To_All_Servers();

    GVC_Increase_Global_View(  GVC_Global_Preinstall_Proof_View() );

}

void GVC_Initialize() {

    int32u si;

    for ( si = 0; si <= NUM_SITES; si++ ) {
	UTIL_Stopwatch_Start( &(Forward_gvc_stopwatch[NUM_SITES+1]));
    }

    Alarm(DEBUG,"GVC_Initialize\n");

    E_queue( GVC_Send_Proof, 0, NULL, timeout_global_view_change_send_proof );
    
    My_old_global_view_proof = GVC_Global_Preinstall_Proof_View();

}

void GVC_Send_Proof_To_All_Servers() {
    
    /* Send the messages that constitute proof of the latest view that has
     * preinstalled. */
    
    int32u pview;
    int32u my_view;
    int32u si;
    signed_message *gvc;
    signed_message *my_gvc;
    int32u count;

    pview = GVC_Global_Preinstall_Proof_View();
    my_view = GVC_Get_View( GLOBAL.Global_VC[VAR.My_Site_ID] );

    my_gvc = GLOBAL.Global_VC[VAR.My_Site_ID]; 

    if ( my_view < GLOBAL.View ) {
	/* Resend the signature share */
	if ( GLOBAL.Global_VC_share[VAR.My_Server_ID] != NULL ) {
	    UTIL_Site_Broadcast( 
		    GLOBAL.Global_VC_share[VAR.My_Server_ID] );
	}
    }

    /* Always send my message regardless of the value of the view */
    if ( my_gvc != NULL ) {
	UTIL_Site_Broadcast( my_gvc );
	UTIL_Send_To_Site_Servers_With_My_ID( my_gvc );
    }

    /* Send 2f+1 messages that constitute proof */
    count = 0;
    for ( si = 1; si <= NUM_SITES; si++ ) {
	gvc = GLOBAL.Global_VC[si];
	if ( gvc != NULL ) {
	    if ( GVC_Get_View(gvc) >= pview ) {
		count++;
		if ( si != VAR.My_Site_ID ) {
		    /* Send our site id 1 time */
		    UTIL_Site_Broadcast( gvc ); /* Local */
		    UTIL_Send_To_Site_Servers_With_My_ID( gvc ); /* WA */
		}
		/* To optimize, we can reduce messages sent by stopping when count
		 * reaches enough messages to constitute proof. */
	    }
	}
    }
 
}

void GVC_Send_Proof( int32 dummy, void *dummyp ) {

    /* Send the messages that constitute proof of the latest view change. */
 
    /* These are threshold signed, trusted vc messages. */

    /* Periodically, print the view for which I have proof. */

    int32u view;

    view = GVC_Global_Preinstall_Proof_View();

    if ( view != My_old_global_view_proof ) {
	Alarm(DEBUG,"%d %d New Global View proof %d, my global view %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, view, GLOBAL.View);
	My_old_global_view_proof = view; 	
    }
    
    GVC_Send_Proof_To_All_Servers();

    E_queue( GVC_Send_Proof, 0, NULL, timeout_global_view_change_send_proof );

}

/* Construct a new global view change message that will be used to generate a
 * threshold signature. */
signed_message* Construct_Global_View_Change_Message() {

    signed_message *global_view_change;
    
    /* make a new message */
    global_view_change = UTIL_New_Signed_Message();
    
    /* assign the view */
    ((global_view_change_message*)(global_view_change + 1))->global_view = 
	GLOBAL.View;

    /* put in the length */
    global_view_change->len = sizeof(global_view_change_message);

    /* type */
    global_view_change->type = SITE_GLOBAL_VIEW_CHANGE_TYPE;

    /* site id */
    global_view_change->site_id = VAR.My_Site_ID;

    /* machine id */
    global_view_change->machine_id = 0;

    /* NOTE: This is a signature share message so we don't sign it. This is
     * done in the threshold_sign code. */

    return global_view_change;

}

void GVC_Process_Message( signed_message *mess ) {

    GVC_Increase_Global_View( GVC_Global_Preinstall_Proof_View() );

    /* Forward any view change messages */    
    if ( mess->type == SITE_GLOBAL_VIEW_CHANGE_TYPE ) {
	/* We should site broadcast any messages that come from a server
	 * outside of our site. */
	if ( mess->site_id != VAR.My_Site_ID ) {
	    /* If I haven't forwarded a message for a while, then forward it.
	     * */
	    UTIL_Stopwatch_Stop(
		    &(Forward_gvc_stopwatch[mess->site_id]) );
	    if ( UTIL_Stopwatch_Elapsed( 
		    &(Forward_gvc_stopwatch[mess->site_id]))
	         > 0.05 ) {
		UTIL_Stopwatch_Start(
		    &(Forward_gvc_stopwatch[mess->site_id]) );
		UTIL_Site_Broadcast( mess );
	        Alarm(DEBUG,"FORWARD G VC MESS from %d v%d 1:%d 2:%d 3:%d\n",
		    mess->site_id, GVC_Get_View(mess),
		    GVC_Get_View(GLOBAL.Global_VC[1]),
		    GVC_Get_View(GLOBAL.Global_VC[2]),
		    GVC_Get_View(GLOBAL.Global_VC[3]));
	    }	
	}
    }

}

