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

/* Handles receiving prepare certificates during PENDING view changes. We take
 * advantage of a guarantee that the number of prepare certificates is bounded
 * by the size of the window. Therefore, for each server we allocate a simple
 * static array of receiver slots for N prepare certificates where we are
 * guaranteed to have N or less prepare certificates total. */

#include "data_structs.h"
#include <string.h>
#include "apply.h"
#include "util/memory.h"
#include "utility.h"
#include "util/alarm.h"
#include "prepare_certificate_receiver.h"

/* external variables */
extern server_variables VAR;

extern network_variables NET;

extern global_data_struct GLOBAL;

extern pending_data_struct PENDING;


/* For each prepare_certificate that a server has claimed that it has (and will
 * send) we allocate space to store the pre-preapare and prepare messages that
 * composed this prepare certificate. */
typedef struct dummy_pcert_receiver_slot {
    prepare_certificate_struct certificate;
    int32u is_applied;				/* Has this been applied? */
    int32u local_view;
    int32u global_view;
    int32u seq_num;
    byte update_digest[ DIGEST_SIZE ];
} pcert_slot_struct;

#define NUM_PCERT_SLOTS (NUM_SERVER_SLOTS)*(5+LOCAL_WINDOW)

/* For each server, we keep the following structure which contains a holder for
 * the prepare certificates that this server must send. */
typedef struct dummy_pcert_array {
    int32u num_prepare_certificates;        /* The number of prepare
					     * certificates that we are 
					     * receiving. */
    pcert_slot_struct certificate[NUM_PCERT_SLOTS]; /* A list of certificates */
} pcert_array_struct;

pcert_array_struct pcert_array;

/* Local Functions */
void PCRCV_Clear_Pcert_Slot( pcert_slot_struct *slot );
void PCRCV_Process_Generic( signed_message *mess ); 
void  PCRCV_Apply_Proposal_To_Slot( pcert_slot_struct *slot, signed_message
	*proposal ); 
void PCRCV_Apply_Prepare_Cert_Component_To_Slot( pcert_slot_struct *slot, 
	signed_message *mess ); 
int32u PCRCV_Already_Contains( int32u local_view,
      int32u global_view, int32u seq_num, byte *update_digest ); 

 
void APPLY_Clear_Prepare_Certificate( prepare_certificate_struct *pcert ) {

    int32u i;

    UTIL_PURGE(&pcert->pre_prepare);

    for ( i = 1; i <= NUM_SERVERS_IN_SITE; i++) {
	UTIL_PURGE(&pcert->prepare[i]);
    }

}
 
void PCRCV_Clear_Pcert_Slot( pcert_slot_struct *slot ) {

    int i;
    
    slot->is_applied = 0;
    slot->local_view = 0;
    slot->global_view = 0;
    slot->seq_num = 0;

    for ( i = 0; i < DIGEST_SIZE; i++ ) {
	slot->update_digest[ i ] = 0;
    }
    
    /* Clear the prepare_certificate */
    APPLY_Clear_Prepare_Certificate( &(slot->certificate) );
    
}

void PCRCV_Clear_Pcert_Array() {

    /* Clear a pcert array */

    int32u index;

    for ( index = 0; index < NUM_PCERT_SLOTS; index++ ) {
	/* Clear the certificate */
	PCRCV_Clear_Pcert_Slot(&(pcert_array.certificate[index]));
    }

    pcert_array.num_prepare_certificates = 0; /* Ready */ 
}

int32u PCRCV_Already_Contains( int32u local_view,
      int32u global_view, int32u seq_num, byte *update_digest ) {

    int i;
    pcert_slot_struct *slot;

    for ( i = 0; i < pcert_array.num_prepare_certificates; i++ ) {
	slot = &(pcert_array.certificate[i]);
	if ( slot->local_view == local_view &&
	     slot->global_view == global_view && 
	     slot->seq_num == seq_num &&
	     OPENSSL_RSA_Digests_Equal( slot->update_digest, update_digest ) ) {
	    return 1;
	}
    }
    
    return 0;
}

/* Add the description of a prepare certificate (or proposal) that needs to be
 * received as described by a view change report message (CCS) */
void PCRCV_Configure_Prepare_Certificate_Receiver( int32u local_view,
      int32u global_view, int32u seq_num, byte *update_digest ) {

    pcert_slot_struct *slot;

    if ( PCRCV_Already_Contains( local_view,global_view, seq_num,update_digest ) ) {
	return;
    }
   
    /* We are not waiting for this prepare certificate, so allocate a receiver
     * slot. */
    pcert_array.num_prepare_certificates++;
    
    /* Get the next empty slot */
    slot = &(pcert_array.certificate[pcert_array.num_prepare_certificates-1]);
    
    /* Configure the slot  */
    slot->is_applied = 0;
    slot->local_view = local_view;
    slot->global_view = global_view;
    slot->seq_num = seq_num;
    memcpy( slot->update_digest, update_digest, DIGEST_SIZE );


    Alarm(DEBUG,"PCRCV_Configure_Prepare_Certificate_Receiver\n");
    
}

/* Process a message that may be a part of a prepare certificate or a proposal
 * that the receiver data structure needs. */
void PCRCV_Process_Message( signed_message *mess ) {

    /* Process the message based on type. */

    if ( mess->type == PROPOSAL_TYPE || 
	 mess->type == PRE_PREPARE_TYPE ||
	 mess->type == PREPARE_TYPE ) {
	PCRCV_Process_Generic( mess );
    }

}

/* Process any of the messages. */
void PCRCV_Process_Generic( signed_message *mess ) {

    /* Iterate over all receiver slots */
    pcert_slot_struct *slot;
    int32u i;

    /* iterate over all slots in the array where there is something that is
     * needed */
    for ( i = 0; i < pcert_array.num_prepare_certificates; i++ ) {

	slot = &(pcert_array.certificate[i]);
	if ( !slot->is_applied ) {
	    if ( mess->type == PROPOSAL_TYPE ) {
		PCRCV_Apply_Proposal_To_Slot( slot, mess );
	    } else {
		/* The message might contribute to a prepare certificate. */
		PCRCV_Apply_Prepare_Cert_Component_To_Slot( slot, mess );
		/* Check if slot should be applied -- it's possible
		 * that the message that was added created a prepare
		 * certificate and now this prepare certificate can be
		 * applied to the global data structures  */
	    }
	}
    }

}

/* Apply a proposal to the receiving data structures. */
void PCRCV_Apply_Proposal_To_Slot( pcert_slot_struct *slot, 
	signed_message *proposal ) {
    
    /* If the proposal has the same global view as the slot, then it can
     * be used to mark a slot as applied. */

    proposal_message *proposal_specific;

    proposal_specific = (proposal_message*)(proposal+1);
    
    if ( slot->global_view == proposal_specific->global_view ||
         slot->seq_num == proposal_specific->seq_num ) {
        /* Mark the slot as applied */
        slot->is_applied = 1;
    }

}

/* Apply a prepare or pre_prepare message to the receiving data structure slot. */
void PCRCV_Apply_Prepare_Cert_Component_To_Slot( pcert_slot_struct *slot, 
	signed_message *mess ) {
    
    byte digest_buf[ DIGEST_SIZE ];
    byte* digest;
    pre_prepare_message *pp_specific;
    prepare_message *p_specific;
    int32u global_view;
    int32u local_view;
    int32u seq_num;
    pending_slot_struct *pending_slot;
    
    if ( mess->type == PRE_PREPARE_TYPE ) {
	/* Make digest */
	pp_specific = (pre_prepare_message*)(mess+1);
	OPENSSL_RSA_Make_Digest( 
		(void*)(pp_specific+1),
		mess->len - sizeof(pre_prepare_message),
		digest_buf );
	digest = digest_buf;
	global_view = pp_specific->global_view;
	local_view = pp_specific->local_view;
	seq_num = pp_specific->seq_num; 
    } else {
	/* Prepare type -- the digest is in the messsage */
	p_specific = (prepare_message*)(mess+1);
	digest = p_specific->update_digest;
	global_view = p_specific->global_view;
	local_view = p_specific->local_view;
	seq_num = p_specific->seq_num; 
    }	

    if ( global_view != slot->global_view ||
         local_view != slot->local_view ||
         seq_num != slot->seq_num || 
	 ! OPENSSL_RSA_Digests_Equal( digest, slot->update_digest ) ) {

	//OPENSSL_RSA_Print_Digest(digest);
	//OPENSSL_RSA_Print_Digest(slot->update_digest);

	/* The message does not match */
	return;
    }

    /* The message can be added to the prepare certificate */
    if ( mess->type == PRE_PREPARE_TYPE ) {
	if ( slot->certificate.pre_prepare == NULL ) {
	    Alarm(PRINT,"Adding PRE_PREPARE %d %d %d\n",mess->len,mess->machine_id,mess->site_id);
	    slot->certificate.pre_prepare = mess;
	    inc_ref_cnt(mess);
	}
    } else if ( mess->type == PREPARE_TYPE ) {
	if ( slot->certificate.prepare[mess->machine_id] == NULL ) {
	    Alarm(PRINT,"Adding PREPARE %d %d %d\n",mess->len,mess->machine_id,mess->site_id);
	    slot->certificate.prepare[mess->machine_id] = mess;
	    inc_ref_cnt(mess);
	}
    }

    /* Test to see if a prepare certificate exists */
    if ( APPLY_Prepare_Certificate_Ready( slot->certificate.pre_prepare, 
	       slot->certificate.prepare, 0 ) ) { 
	/* There is a prepare certificate. */

	Alarm(PRINT, "Prepare Certificate Receiver received a"
	       " prepare certificate.\n");

	slot->is_applied = 1;
	pending_slot = UTIL_Get_Pending_Slot( slot->seq_num );
	/* Move the prepare certificate to the pending data structures */
	APPLY_Move_Prepare_Certificate( &(slot->certificate.pre_prepare), 
		slot->certificate.prepare, pending_slot  );
    } 
 
}



