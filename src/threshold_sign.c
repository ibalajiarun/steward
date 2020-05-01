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

/* Process Threshold Crypto Messages. */

#include "data_structs.h"
#include "error_wrapper.h"
#include "threshold_sign.h"
#include "utility.h"
#include "util/alarm.h"
#include "apply.h"
#include "construct_collective_state_protocol.h"
#include "validate.h"
#include "util/memory.h"
#include <string.h>

extern server_variables VAR;

util_stopwatch combine_stopwatch;

/* Local funtctions */
void THRESH_Proposal_Share( signed_message *mess ); 
void THRESH_Accept_Share( signed_message *mess );
void THRESH_Union_Share( signed_message *mess);
void THRESH_Global_View_Change_Share(signed_message *mess); 
void THRESH_Local_View_Proof_Share( signed_message *mess ); 

void THRESH_Process_Threshold_Share( signed_message *mess ) {

    /* NOTE: A threshold share could be for many types of messages. We must
     * determine what type of message the share is for and store the share in a
     * location based on its type. When we have received enough shares, we
     * combine them, verify the signature, and blacklist nodes if we determine
     * that a node sent a bad share. */

    signed_message *content;
    
    content = (signed_message*)(((sig_share_message*)(mess + 1))+1);
    
    switch ( content->type ) {
	/* Based on type, process share. */
	case PROPOSAL_TYPE:
	    THRESH_Proposal_Share( mess );
	    return;
	case ACCEPT_TYPE:
	    THRESH_Accept_Share( mess );
	    return;
        case CCS_UNION_TYPE:
	    THRESH_Union_Share(mess);
	    return;
        case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	    THRESH_Global_View_Change_Share(mess);
	    return;
        case SITE_LOCAL_VIEW_PROOF_TYPE:
	    THRESH_Local_View_Proof_Share(mess);
	    return;
	default:
	    Alarm(DEBUG,"sig share message with type %d\n",
		    content->type );
	    INVALID_MESSAGE("");
    }

}

void THRESH_Invoke_Threshold_Signature( signed_message *mess ) {
    
  /* Make a threshold signature share for this message and send this share. */ 
    
    signed_message *share;
    sig_share_message *share_specific;
    signed_message *content;
    byte digest[DIGEST_SIZE];

    share = UTIL_New_Signed_Message();

    share_specific = (sig_share_message*)(share+1);
    content = (signed_message*)(share_specific+1);
    
    share->len = (sizeof(sig_share_message) + sizeof(signed_message) + 
		  mess->len);

    share->type       = SIG_SHARE_TYPE;
    share->site_id    = VAR.My_Site_ID;
    share->machine_id = VAR.My_Server_ID;
    
    /* Copy the messsage that the share is for */
    memcpy( (void*)content, (void*)mess, 
	    mess->len + sizeof(signed_message) );
    
    /* The signature share is on all of mess except the signature */     
    UTIL_Stopwatch_Start( &combine_stopwatch );

    OPENSSL_RSA_Make_Digest( 
	    (char*)content + SIGNATURE_SIZE, 
	    content->len + sizeof(signed_message) - SIGNATURE_SIZE, 
	    digest );

    //OPENSSL_RSA_Print_Digest(digest);
    
    TC_Generate_Sig_Share((byte*)content, digest); 

    UTIL_Stopwatch_Stop( &combine_stopwatch );

    if ( VAR.My_Site_ID == 1 && VAR.My_Server_ID == 2) {
	Alarm(DEBUG,"%d %d sig_share_gen: %f type: %d seq: %d\n",
		VAR.My_Site_ID,VAR.My_Server_ID,
		UTIL_Stopwatch_Elapsed( &combine_stopwatch ),
		mess->type, ((proposal_message*)(mess+1))->seq_num ); 
    }

    /* Print share */
#if 0 
    Alarm(PRINT,"Server: %d\n",VAR.My_Server_ID);
    for ( c = 0; c < 128; c++ ) { 
	Alarm(PRINT,"%x",((char*)content)[c]);
    }
    Alarm(PRINT,"\n");
#endif
    
    UTIL_RSA_Sign_Message( share );
    APPLY_Message_To_Data_Structs( share );
    UTIL_Site_Broadcast( share );

    dec_ref_cnt( share );
}

/* These functions are not used -- However, they are convenient for watching
 * shares passing through the system. */

void THRESH_Proposal_Share( signed_message *mess ) {

    sig_share_message *share;
    signed_message *proposal;

    share = (sig_share_message*)(mess + 1);

    /* The share is for a proposal. */
    proposal = (signed_message*)(share + 1);

}
 

void THRESH_Accept_Share( signed_message *mess ) {
 
}

void THRESH_Union_Share(signed_message *mess) {

}

void THRESH_Global_View_Change_Share(signed_message *mess) {

}

void THRESH_Local_View_Proof_Share( signed_message *mess ) {
 
} 

util_stopwatch combine_stopwatch;

/* Construct a new threshold signed message, if possible. Takes an array of
 * signed_messages that are signature shares. The array should contain the
 * number of shares necessary to create a signature share. The function
 * combines these signature shares. If the resulting threshold signature
 * verifies, the function returns 1 and stores the signature in the provided
 * destination. If the resulting signature does not verify, then the function
 * returns 0 and blacklists all of the servers that contributed invalid
 * signature shares. It also removes any invalid signature shares from the
 * array. */
int32u THRESH_Attempt_To_Combine( signed_message **sig_share, 
      signed_message *dest_mess ) { //byte *signature_dest ) {

    int32u si;
    signed_message *share;
    signed_message *content;
    byte digest[DIGEST_SIZE];
    byte *signature_dest;

    signature_dest = (byte*)dest_mess;
    
    share = NULL;
    content = NULL;

    Alarm(DEBUG,"%d %d THRESH_Attempt_To_Combine num_servers: %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, 
	    NUM_SERVERS_IN_SITE );

    TC_Initialize_Combine_Phase( NUM_SERVERS_IN_SITE + 1 );
 
    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	if ( sig_share[si] != NULL ) {
	    /* Add the share. */
	    share = sig_share[si]; /* pointer to share */
	    if ( share->site_id != VAR.My_Site_ID )  {
		Alarm(DEBUG,"ATTEMPT TO COMBINE SHARE NOT FROM MY SITE\n");
	    }
	    content = (signed_message*)((byte*)(share+1) + 
					sizeof(sig_share_message));
#if 0 
	    Alarm(PRINT,"adding share %d %d\n",si,share);
	    for ( c = 0; c < 128; c++ ) { 
		Alarm(PRINT,"%x",((char*)content)[c]);
	    }
	    Alarm(PRINT,"\n");
#endif
	    TC_Add_Share_To_Be_Combined( si, 
				/* location of actual signature share */ 
					 (byte*)content );
	}
    }

    if ( share == NULL || content == NULL ) {
	return 0;
    }
    
    /* Make a digest based on one of the signature shares */
    OPENSSL_RSA_Make_Digest( 
	    (byte*)(content) + SIG_SHARE_SIZE, 
	    content->len + sizeof(signed_message) - 
	    SIG_SHARE_SIZE,
	    digest );

    /*OPENSSL_RSA_Print_Digest(digest);*/
    
    /* Combine the shares */    
    UTIL_Stopwatch_Start( &combine_stopwatch );
    TC_Combine_Shares( signature_dest, digest );
  
    /* Copy the data into the new message */
    memcpy( (byte*)(dest_mess) + SIGNATURE_SIZE,
	    (byte*)content + SIGNATURE_SIZE,
	    content->len + sizeof(signed_message) - SIGNATURE_SIZE );

    UTIL_Stopwatch_Stop( &combine_stopwatch );

    /* Check if the proposal verifies */
    if(!VAL_Validate_Message(dest_mess, sizeof(signed_message) + 
			     dest_mess->len)) {
      Alarm(DEBUG, "Combined one doesn't validate!\n");
    }
    else 
      Alarm(DEBUG, "Combined message passes validation!\n");

    /* If the proof does not verifiy, we must enter a phase where we
     * check all shares to make sure that they are valid. Any share
     * that is not valid must be removed from the sig_shares array AND
     * the server that contributed the invalid share sould be
     * blacklisted. This is not currently coded. */

    /* Clean up */
    TC_Destruct_Combine_Phase( NUM_SERVERS_IN_SITE + 1 );
  
    return 1;
}
