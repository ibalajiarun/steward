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

/* Message validation functions. These functions check to make sure messages
 * came from the server or site that should have sent them and check to make
 * sure that the lengths are correct. */

#include "validate.h"
#include "data_structs.h"
#include "error_wrapper.h"
#include "openssl_rsa.h"
#include "construct_collective_state_protocol.h"
#include "construct_collective_state_util.h"
#include "utility.h"
#include "util/alarm.h"

extern server_variables VAR;

/* Local Functions */
int32u VAL_Signature_Type( int32u message_type ); 

int32u VAL_Validate_Sender( int32u sig_type, int32u sender_id ); 

int32u VAL_Validate_Signed_Message( signed_message *mess, int32u num_bytes, 
       int32u verify_signature ); 

int32u VAL_Validate_Update( update_message *update, int32u num_bytes ); 

int32u VAL_Validate_Query_Message(query_message *query, int32u num_bytes);

int32u VAL_Validate_Pre_Prepare( pre_prepare_message *pre_prepare, 
	int32u num_bytes ); 

int32u VAL_Validate_Prepare( prepare_message *prepare, int32u num_bytes ); 

int32u VAL_Validate_Sig_Share( sig_share_message *sig_share, 
	int32u num_bytes ); 

int32u VAL_Validate_Proposal( proposal_message *proposal, 
	int32u num_bytes, int32u verify_signature ); 

int32u VAL_Validate_Accept( accept_message *accept, 
			    int32u num_bytes ); 

int32u VAL_Validate_Global_View_Change( global_view_change_message *gvc, 
			    int32u num_bytes ); 

int32u VAL_Validate_Local_View_Proof( local_view_proof_message *lvp, 
			    int32u num_bytes ); 

int32u VAL_Validate_L_New_Rep( l_new_rep_message *l_new_rep,
	int32u num_bytes ); 

int32u VAL_Validate_Local_Reconciliation( local_reconciliation_message *l_new_rep,
	int32u num_bytes ); 

int32u VAL_Validate_Global_Reconciliation(global_reconciliation_message *grecon, int32u num_bytes);

int32u VAL_Validate_Ordered_Proof( ordered_proof_message *ordered_proof, int32u num_bytes ); 

int32u VAL_Validate_CCS_Invocation_Message( signed_message *invocation,
	int32u num_bytes ); 

/* JK Added */
int32u VAL_Validate_CCS_Report_Message(ccs_report_message *report, 
				      int32u num_bytes);

int32u VAL_Validate_CCS_Description_Message(ccs_description_message *description,
					   int32u num_bytes);

int32u VAL_Validate_CCS_Union_Message(signed_message *m,  
				     int32u num_bytes,int32u verify_signature);

int32u VAL_Is_Valid_Signature( int32u sig_type, int32u sender_id, 
	int32u site_id, signed_message *mess );
	




/* Determine if the message type is valid and if so return which type of
 * signature is on the message, a client signature, a server signature, or a
 * threshold signature. 
 * 
 * returns: VAL_SIG_TYPE_SERVER, VAL_SIG_TYPE_CLIENT, VAL_SIG_TYPE_SITE, or
 * VAL_TYPE_INVALID */
int32u VAL_Signature_Type( int32u message_type ) {
    /* Return the type of the signature based on the type of the message. If
     * the type is not found, then return TYPE_INVALID */
    int32u mt;

    mt = message_type;

    if ( mt == PRE_PREPARE_TYPE || 
	 mt == PREPARE_TYPE ||
	 mt == SIG_SHARE_TYPE ||
	 mt == L_NEW_REP_TYPE || 
	 mt == ORDERED_PROOF_TYPE ||
	 mt == LOCAL_RECONCILIATION_TYPE ||
         mt == CCS_INVOCATION_TYPE ||
	 mt == CCS_REPORT_TYPE ||
	 mt == CCS_DESCRIPTION_TYPE ||
	 mt == GLOBAL_RECONCILIATION_TYPE
	 ) {
	return VAL_SIG_TYPE_SERVER;
    }

    if ( mt == PROPOSAL_TYPE ||
	 mt == ACCEPT_TYPE   ||
	 mt == CCS_UNION_TYPE ||
         mt == SITE_GLOBAL_VIEW_CHANGE_TYPE ||
         mt == SITE_LOCAL_VIEW_PROOF_TYPE ) {
	return VAL_SIG_TYPE_SITE;
    }	

    if ( mt == UPDATE_TYPE ||
	 mt == QUERY_TYPE ) {
	return VAL_SIG_TYPE_CLIENT;
    }
    
    return VAL_TYPE_INVALID;
} 

/* Determine if the sender is valid depending on the specified signature type.
 * 
 * return: 1 if sender is valid, 0 if sender is not valid */
int32u VAL_Validate_Sender( int32u sig_type, int32u sender_id ) {

    if ( sender_id < 1 ) 
	return 0;

    if ( sig_type == VAL_SIG_TYPE_SERVER &&
         sender_id <= NUM_SERVERS_IN_SITE ) {
	return 1;
    } 
    
    if ( sig_type == VAL_SIG_TYPE_SITE &&
	 sender_id <= NUM_SITES ) {
	return 1;
    }

    if ( sig_type == VAL_SIG_TYPE_CLIENT &&
	 sender_id <= NUM_CLIENTS ) {
	return 1;
    }	

    return 0;
}

/* Determine if a signed message is valid. */
int32u VAL_Validate_Signed_Message( signed_message *mess, int32u num_bytes, 
	int32u verify_signature ) {

    int32u sig_type;
    int32u sender_id;

    if ( num_bytes < (sizeof(signed_message)) ) {
	VALIDATE_FAILURE("");
        return 0;
    }
    
    if ( num_bytes != mess->len + sizeof(signed_message) ) {
	VALIDATE_FAILURE("");
 	return 0;
    }

    sig_type = VAL_Signature_Type( mess->type );

    if ( sig_type == VAL_TYPE_INVALID ) {
	VALIDATE_FAILURE("");
 	return 0;
    }

    if ( sig_type == VAL_SIG_TYPE_SERVER && 
	    mess->site_id != VAR.My_Site_ID && 
	    mess->type != ORDERED_PROOF_TYPE && 
	    mess->type != GLOBAL_RECONCILIATION_TYPE  ) {
	VALIDATE_FAILURE("");
	return 0;
    }
    
    if ( sig_type == VAL_SIG_TYPE_SERVER ||
	 sig_type == VAL_SIG_TYPE_CLIENT ) {
	sender_id = mess->machine_id;
    } else {
	/* threshold signed */
	sender_id = mess->site_id;
    }
    
    if ( !VAL_Validate_Sender( sig_type, sender_id ) ) {
	VALIDATE_FAILURE("");
 	return 0;
    }
    
    if ( !VAL_Is_Valid_Signature( sig_type, sender_id, mess->site_id, mess ) )
    {
	VALIDATE_FAILURE("");
        return 0;
    }
    
    return 1; /* Passed all checks */
}

/* Determine if the signature is valid. Assume that the lengths of the message
 * is okay. */
int32u VAL_Is_Valid_Signature( int32u sig_type, int32u sender_id, 
	int32u site_id, signed_message *mess ) {

  byte digest[DIGEST_SIZE];

    if ( sig_type == VAL_SIG_TYPE_SERVER ) {
	/* Check an RSA signature using openssl. A server sent the message. */
	return OPENSSL_RSA_Verify( 
		 ((byte*)mess) + SIGNATURE_SIZE,
		 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
		 (byte*)mess, 
		 sender_id,
		 site_id,
		 RSA_SERVER
		); 
    }
   
    if ( sig_type == VAL_SIG_TYPE_CLIENT ) {
	/* Check an RSA signature using openssl. A client sent the message. */
	return OPENSSL_RSA_Verify( 
		 ((byte*)mess) + SIGNATURE_SIZE,
		 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
		 (byte*)mess, 
		 sender_id,
		 site_id,
		 RSA_CLIENT
		); 
    }

    if ( sig_type == VAL_SIG_TYPE_SITE ) {
	/* Check a Threshold signature using the tc library. A site threshold
	 * signed this message. */
#if EMULATE_NON_REP_SITE

	/* NOTE: When using emulation we do not verify threshold signatures
	 * because they cannot be generated by a single emulating server. */

	return 1;
#endif
	/* Compute the digest of the message and copy it into the digest
	 * field */
	OPENSSL_RSA_Make_Digest(
	   ((byte*)mess) + SIGNATURE_SIZE, /* data */
	   mess->len + sizeof(signed_message) - SIGNATURE_SIZE, /* length */
	   digest /* destination */
	  );

	/* Verify the threshold signature. */
	if ( TC_Verify_Signature( 
		    site_id,	  /* site id */
		    (byte*)mess,  /* the signature*/
		    digest	  /* digest of what was signed */ ) 
		) {
	    Alarm(DEBUG,"Verified thres sig\n");
	    return 1;
	} else {
	    Alarm(DEBUG,"Failed to verify thes sig\n");
	}
    
    }

    return 0;
}

/* Determine if an update is valid */
int32u VAL_Validate_Update( update_message *update, int32u num_bytes ) {

    /* Check to determine if the update is valid. We have already checked to
     * see if the signature verified. We only need to make sure that the packet
     * is large enough for the timestamp. */

    if ( num_bytes < (sizeof(update_message)) ) {
	VALIDATE_FAILURE("");
        return 0;
    }

    return 1;

}

/* Determine if a query is valid */
int32u VAL_Validate_Query_Message( query_message *query, int32u num_bytes ) {

    /* Check to determine if the query is valid. We have already checked to
     * see if the signature verified. We only need to make sure that the packet
     * is large enough for the timestamp. */

    if ( num_bytes < (sizeof(query_message)) ) {
	VALIDATE_FAILURE("");
        return 0;
    }
    
    return 1;
}

/* Determine if a Pre-Prepare is valid */
int32u VAL_Validate_Pre_Prepare( pre_prepare_message *pre_prepare,
       int32u num_bytes ) {

    if ( num_bytes < sizeof(pre_prepare_message) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }

    if ( pre_prepare->seq_num < 0 ) {
	VALIDATE_FAILURE("");	
	return 0;
    }

    /* An update follows -- this is just a signed message with an update_message
     * structure following it. */
    if ( ! VAL_Validate_Signed_Message( (signed_message*)(pre_prepare + 1),
	       num_bytes - (sizeof(pre_prepare_message)), 1 ) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }
 
    if ( num_bytes - (sizeof(pre_prepare_message)) < (sizeof(signed_message)) ) {
	/* Safety check */
	VALIDATE_FAILURE("");	
	return 0;
    }
    
    if ( ! VAL_Validate_Update( (update_message*)((byte*)(pre_prepare + 1) + 
		sizeof(signed_message)),
	       num_bytes - (sizeof(pre_prepare_message)) -
	       (sizeof(signed_message))  ) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }

    return 1;
}

/* Determine if a prepare message is valid */
int32u VAL_Validate_Prepare( prepare_message *prepare, 
	int32u num_bytes ) {

    if ( num_bytes != sizeof(prepare_message) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }
 
    if ( prepare->seq_num < 1 ) {
	VALIDATE_FAILURE("");	
	return 0;
    }
 
    return 1;
}

int32u VAL_I_Am_Combiner() {
    /* Am I a combiner? */
    if ( UTIL_I_Am_Representative() ) {
	return 0;
    }
    if ( VAR.My_Server_ID <= VAR.Faults + 1) {
	return 1;
    }
    if ( UTIL_Representative() <= VAR.Faults + 1 && 
	 VAR.My_Server_ID == VAR.Faults + 2 ) {
	return 1;
    }
    return 0;
}

/* Determine if sig share is valid. */
int32u VAL_Validate_Sig_Share( sig_share_message *sig_share, 
	int32u num_bytes ) {

    signed_message *content;
#if 0
    proposal_message* proposal_specific; 
#endif

    if ( num_bytes < sizeof(sig_share_message) + sizeof(signed_message) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }

    content = (signed_message*)(sig_share + 1);
    
    if ( num_bytes != content->len + sizeof(signed_message) 
	    + sizeof(sig_share_message) ){
	VALIDATE_FAILURE("");	
	return 0;
    }
 
    if ( content->site_id != VAR.My_Site_ID ){
	VALIDATE_FAILURE("");	
	return 0;
    }
    
    switch (content->type) {
          case PROPOSAL_TYPE:
            if ( !VAL_Validate_Proposal( 
				  (proposal_message*)(content+1), 
		num_bytes - sizeof(sig_share_message) - sizeof(signed_message), 
		    1) ) {
		VALIDATE_FAILURE("");
		return 0;
	    }
	    /* Should this server accept a signature share for this proposal? */
#if 0
	    proposal_specific = (proposal_message*)(content+1);
	    if ( UTIL_I_Am_Representative() && proposal_specific->seq_num % 2 == 0 ) {
		return 1;
	    } 
	    if ( VAL_I_Am_Combiner() && proposal_specific->seq_num % 2 == 1 ) {
		return 1;
	    }
	    Alarm(DEBUG,"VALIDATE PROPOSAL SIG SHARE\n");
	    return 0;

	    JWL SPEED -- took out this optimization

#endif     

	    return 1;
	case ACCEPT_TYPE:
	    Alarm(DEBUG,"%d %d PRE VALIDATE ACCEPT SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    if ( !VAL_Validate_Accept( 
		(accept_message*)(content+1),
		    num_bytes - sizeof(sig_share_message) - sizeof(signed_message) 
		    ) ) { 
		VALIDATE_FAILURE("");
		return 0;
	    }
	    Alarm(DEBUG,"%d %d DONE VALIDATE ACCEPT SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    return 1;
	case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	    Alarm(DEBUG,"%d %d PRE VALIDATE GLOBAL_VIEW_CHANGE SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    if ( !VAL_Validate_Global_View_Change( 
		(global_view_change_message*)(content+1),
		    num_bytes - sizeof(sig_share_message) - sizeof(signed_message) 
		    ) ) { 
		VALIDATE_FAILURE("");
		return 0;
	    }
	    Alarm(DEBUG,"%d %d DONE VALIDATE GLOBAL_VIEW_CHANGE SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    return 1;
	case SITE_LOCAL_VIEW_PROOF_TYPE:
	    Alarm(DEBUG,"%d %d PRE VALIDATE LOCAL_VIEW_PROOF SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    if ( !VAL_Validate_Local_View_Proof( 
		(local_view_proof_message*)(content+1),
		    num_bytes - sizeof(sig_share_message) - sizeof(signed_message) 
		    ) ) { 
		VALIDATE_FAILURE("");
		return 0;
	    }
	    Alarm(DEBUG,"%d %d DONE VALIDATE LOCAL_VIEW_PROOF SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    return 1;
	case CCS_UNION_TYPE:
	    Alarm(DEBUG,"%d %d PRE VALIDATE CCS_UNION SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    if ( !VAL_Validate_CCS_Union_Message( content, 
		 num_bytes - sizeof(sig_share_message) - sizeof(signed_message) 
		    , 1) ) { 
		VALIDATE_FAILURE("");
		return 0;
	    }
	    Alarm(DEBUG,"%d %d DONE VALIDATE CCS_UNION SIG SHARE\n",
		    VAR.My_Site_ID, VAR.My_Server_ID );
	    return 1;
	default:
	    /* The signature share is for an invalid type. */
	    VALIDATE_FAILURE("");
	    return 0;
    }

    return 1;
}

/* Determine if a Proposal Message is valid. */
int32u VAL_Validate_Proposal( proposal_message *proposal, 
			      int32u num_bytes, int32u verify_signature ) {

    Alarm(DEBUG,"%d %d VAL_Validate_Proposal\n",
	    VAR.My_Site_ID, VAR.My_Server_ID);

    if ( num_bytes < sizeof(proposal_message) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    /* An update follows -- this is just a signed message with an update_message
     * structure following it. */
    if ( ! VAL_Validate_Signed_Message( (signed_message*)(proposal + 1),
	       num_bytes - (sizeof(proposal_message)), verify_signature ) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    if ( num_bytes < (sizeof(proposal_message) + sizeof(signed_message)) ) {
	/* Safety check */	
	VALIDATE_FAILURE("");
	return 0;
    }
    
    if ( ! VAL_Validate_Update( (update_message*)((byte*)(proposal + 1)+sizeof(signed_message)),
	       num_bytes - (sizeof(proposal_message)) - 
	        (sizeof(signed_message))) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;
}

/* Determine if an Accept Message is valid */
int32u VAL_Validate_Accept( accept_message *accept, 
	int32u num_bytes ) {

    //if ( VAR.My_Site_ID == 1 ) Alarm(EXIT,"VAL_Validate_Accept Got accept\n");

    if ( num_bytes != sizeof(accept_message) ) {
	Alarm(DEBUG,"Failed to validate accept %d %d\n",
		num_bytes,sizeof(accept_message));
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_Global_View_Change( global_view_change_message *gvc, 
			    int32u num_bytes ) {

    if ( num_bytes != sizeof(global_view_change_message) ) {
	Alarm(DEBUG,"Failed to validate global view change %d %d\n",
		num_bytes,sizeof(accept_message));
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;

}

int32u VAL_Validate_Local_View_Proof( local_view_proof_message *lvp, 
			    int32u num_bytes ) {

    if ( num_bytes != sizeof(global_view_change_message) ) {
	Alarm(DEBUG,"Failed to validate local view proof %d %d\n",
		num_bytes,sizeof(accept_message));
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;

}

int32u VAL_Is_Valid_Context( int32u con ) {

    if ( con == GLOBAL_CONTEXT ||
         con == PENDING_CONTEXT  ) {
	return 1;
    }

    return 0;    
}

int32u VAL_Is_Valid_Report_Entry_Type(int32u type)
{
 
  if( (type == INTERMEDIATE_TYPE) ||
      (type == ORDERED_TYPE))
    return 1;
  
  return 0;
}

/* Determine if a CCS Union Message is valid */
int32u VAL_Validate_CCS_Union_Message( signed_message *ccs_union, 
			      int32u num_bytes, int32u verify_signature ) 
{
  ccs_union_message *union_specific;
  ccs_pending_report_entry *p_base, *p_entry;
  ccs_global_report_entry  *g_base, *g_entry;
  int32u context, num_entries, size, i;

  Alarm(DEBUG, "Validating CCS_Union message...\n");

  union_specific = (ccs_union_message *)(ccs_union + 1);
  context = union_specific->context;

  /* Make sure the message is from either the PENDING or GLOBAL context */
  if( !VAL_Is_Valid_Context( context ) ) {     
    Alarm(DEBUG, "Validate_CCS_Union: Incorrect context: %d\n", context);
    VALIDATE_FAILURE("");
    return 0;
  }
  
  /*
   * In the pending context, we want this message to be from our same global
   * view in addition to the pending view so it's from the same instance of
   * this site as leader site.
   */
  if(context == PENDING_CONTEXT) {
    if ( (union_specific->local_view  != UTIL_Get_View(PENDING_CONTEXT)) ||
	 (union_specific->global_view != UTIL_Get_View(GLOBAL_CONTEXT)) ) {
      Alarm(DEBUG, "View problem.\n");
      VALIDATE_FAILURE("");
      return 0;
    }
  }
  
  if(context == GLOBAL_CONTEXT) {
    if(union_specific->global_view != UTIL_Get_View(GLOBAL_CONTEXT)) {
      Alarm(DEBUG, "Global context, wrong view\n");
      VALIDATE_FAILURE("");
      return 0;
    }
  }

  return 1;

  /* Make sure the reported message length is legitimate based on content */
  if(context == PENDING_CONTEXT)
    size = sizeof(ccs_pending_report_entry);
  else
    size = sizeof(ccs_global_report_entry);

  num_entries = (ccs_union->len - sizeof(ccs_union_message)) / size;

  if(ccs_union->len != (sizeof(ccs_union_message) + (num_entries * size))) {
    Alarm(DEBUG, "CCS_union: Invalid length\n");
    VALIDATE_FAILURE("");
    return 0;
  }

  if(context == PENDING_CONTEXT) {
    for(i = 0; i < num_entries; i++) {
      p_base  = (ccs_pending_report_entry *)(union_specific+1);
      p_entry = (ccs_pending_report_entry *)(p_base + i);

      if(!VAL_Is_Valid_Report_Entry_Type(p_entry->type)) {
	Alarm(VALID_PRINT, "Invalid entry type: %d\n", p_entry->type);
	return 0;
      }
    }
  }
  else {
    for(i = 0; i < num_entries; i++) {
      g_base  = (ccs_global_report_entry *)(union_specific+1);
      g_entry = (ccs_global_report_entry *)(g_base + i);

      if(!VAL_Is_Valid_Report_Entry_Type(g_entry->type)) {
	Alarm(VALID_PRINT, "Invalid entry type: %d\n", g_entry->type);
	return 0;
      }
    }
  }
  
  Alarm(DEBUG, "SUCCESS\n");
  return 1;
}

/* Determine if an L_New_Rep Message is valid */
int32u VAL_Validate_L_New_Rep( l_new_rep_message *l_new_rep, 
	int32u num_bytes ) {

    if ( num_bytes != sizeof(l_new_rep_message) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_Local_Reconciliation( local_reconciliation_message *lrecon,
	int32u num_bytes ) {

    if ( num_bytes != sizeof(local_reconciliation_message) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_Global_Reconciliation(
		  global_reconciliation_message *grecon, int32u num_bytes) 
{

    Alarm(DEBUG,"VAL_Validate_Global_Reconciliation\n");

  if( num_bytes != sizeof(global_reconciliation_message)) {
    VALIDATE_FAILURE("");
    return 0;
  }

  return 1;
}

/* Determine if an ordered proof message is valid */
int32u VAL_Validate_Ordered_Proof( ordered_proof_message *ordered_proof, 
	int32u num_bytes ) {
   
    Alarm(DEBUG,"Validate_Ordered_Proof.\n");
    
    if ( num_bytes < sizeof(ordered_proof_message) + 
	    sizeof(signed_message)*2 + sizeof(proposal_message) + 
	    sizeof(update_message) ) {
	VALIDATE_FAILURE("");	
	return 0;
    }

    /* A proposal follows */
    /* validate the signature */
    if ( ! VAL_Validate_Signed_Message( (signed_message*)(ordered_proof + 1),
	       num_bytes - (sizeof(ordered_proof_message)), 1 ) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

     /* Then validate the proposal */
    if ( ! VAL_Validate_Proposal( (proposal_message*)
	    (((signed_message*)(ordered_proof + 1))+1), 
	    num_bytes - sizeof(signed_message) - sizeof(ordered_proof_message),
	    1 ) ) {
	return 0; 
    }

    return 1;
}

int32u VAL_Validate_CCS_Invocation_Message( signed_message *invocation, 
					   int32u num_bytes ) 
{ 
  ccs_invocation_message *invocation_specific;

  invocation_specific = (ccs_invocation_message *)(invocation+1);

    if ( num_bytes != sizeof(ccs_invocation_message) ) {
	VALIDATE_FAILURE("");
	return 0;
    }

    if ( !VAL_Is_Valid_Context( invocation_specific->context ) ) {
       return 0;
    }       
    
    if( (invocation_specific->local_view != UTIL_Get_View(PENDING_CONTEXT))
	|| (invocation_specific->global_view != 
	    UTIL_Get_View(GLOBAL_CONTEXT)) ) {
      Alarm(VALID_PRINT, "Invalid view.\n");
      return 0;
    }

    if(invocation_specific->aru < 0) {
      VALIDATE_FAILURE("");
      return 0;
    }

    return 1;

    /* Make sure the sender id is the representative */
    if(invocation->machine_id != UTIL_Representative())
      return 0;

    Alarm(DEBUG, "%d %d VAL_Validate_CCS_Invocation_Message\n",
	    VAR.My_Site_ID, VAR.My_Server_ID );
    
    return 1;
}

int32u VAL_Validate_CCS_Report_Message(ccs_report_message *report, int32u nbytes)
{
  int32u i;
  int32u size = 0;
  ccs_global_report_entry *entry;

  Alarm(DEBUG, "%d %d VAL_Validate_CCS_Report_Message  Start\n",
	    VAR.My_Site_ID, VAR.My_Server_ID );
 
  /* If the message is not at least as big as an empty report, drop */
  if(nbytes < sizeof(ccs_report_message)) {
    Alarm(DEBUG, "Validate_CCS_Report: Invalid size: size = %d, nbytes = %d.\n",
	  sizeof(ccs_report_message), nbytes);
    return 0;
  }

  /* If this is not for a valid context, drop */
  if(!VAL_Is_Valid_Context(report->context)) {
    Alarm(DEBUG, "Validate_CCS_Report: Invalid context.\n");
    return 0;
  }

  if( (report->local_view  != UTIL_Get_View(PENDING_CONTEXT)) || 
      (report->global_view != UTIL_Get_View(GLOBAL_CONTEXT)) ) {
    Alarm(VALID_PRINT, "Validate_CCS_Report: Invalid views: %d %d, "
	  "I am in %d %d\n", report->local_view, report->global_view, 
	  UTIL_Get_View(PENDING_CONTEXT), UTIL_Get_View(GLOBAL_CONTEXT));
    return 0;
  }

  if(report->context == GLOBAL_CONTEXT)
    size = sizeof(ccs_global_report_entry);
  else if(report->context == PENDING_CONTEXT)
    size = sizeof(ccs_pending_report_entry);
  
  /* If the claimed len of report list is not accurate */
  if((report->num_entries * size) != (nbytes - sizeof(ccs_report_message))) {
    Alarm(VALID_PRINT, "Validate_CCS_Report: Invalid report list size.\n");
    return 0;
  }

  Alarm(DEBUG," * %d * \n",report->num_entries);
  
  for(i = 1; i <= report->num_entries; i++) {
    entry = Get_Report_Entry(report, i);
    
    if(!VAL_Is_Valid_Report_Entry_Type(entry->type)) {
      Alarm(VALID_PRINT, "Invalid entry type: %d\n", entry->type);
      return 0;
    }
    Alarm(VALID_PRINT,"%d %d VAL_Valididate_Report (entry) seq: %d local_view: %d, "
	  "global_view %d\n",
	  VAR.My_Site_ID, VAR.My_Server_ID, entry->seq, 
	  entry->local_view, entry->global_view ); 
   }
  
  Alarm(DEBUG, "%d %d VAL_Validate_CCS_Report_Message success\n",
	VAR.My_Site_ID, VAR.My_Server_ID );
  
  return 1;
}

int32u VAL_Validate_CCS_Description_Message(ccs_description_message *description,
					   int32u nbytes)
{
  int32u target_size, i;
  int32u servers_seen[NUM_SERVERS_IN_SITE+1];
  description_entry *entry;


  Alarm(DEBUG, "%d %d VAL_Validate_CCS_Description_Message  Start\n",
	    VAR.My_Site_ID, VAR.My_Server_ID );

  if(nbytes < sizeof(ccs_description_message)) {
    Alarm(VALID_PRINT, "Description message too small, nbytes = %d, expected "
	  "at least %d\n", nbytes, sizeof(ccs_description_message));
    return 0;
  }

  if(description->num_entries != (2*VAR.Faults+1)) {
    Alarm(VALID_PRINT, "Invalid num_entries: %d\n", description->num_entries);
    return 0;
  }

  target_size = (sizeof(ccs_description_message) + 
		 description->num_entries * sizeof(description_entry));

  /* The message should be a description plus 2f+1 entries */
  if(nbytes != target_size) {
    Alarm(VALID_PRINT, "Validate_Description: Invalid size.  "
	  "Target = %d, nbytes = %d\n", target_size, nbytes); 
    return 0;
  }

  /* Not a valid context, drop it */
  if(!VAL_Is_Valid_Context(description->context)) {
    Alarm(VALID_PRINT, "Validate_Description: Invalid context.\n");
    return 0;
  }

  /* If not for my view, drop it */
  if( (description->local_view  != UTIL_Get_View(PENDING_CONTEXT)) ||
      (description->global_view != UTIL_Get_View(GLOBAL_CONTEXT)) ) {
    Alarm(VALID_PRINT, "Validate_Description: Invalid view.\n");
    return 0;
  }

  /* 
   * Iterate through description entries.  Make sure the id's are in the
   * correct range, and that no guy is counted twice. 
   */
  for(i = 0; i <= NUM_SERVERS_IN_SITE; i++)
    servers_seen[i] = 0;

  for(i = 1; i <= 2*VAR.Faults+1; i++) {
    entry = Get_Description_Entry(description, i);

    if((entry->machine_id < 1) || (entry->machine_id > NUM_SERVERS_IN_SITE) ||
       (servers_seen[entry->machine_id] == 1)) {
      Alarm(VALID_PRINT, "Validate_Description: Invalid id: %d.\n", 
	    entry->machine_id);
      return 0;
    }
    else
      servers_seen[entry->machine_id] = 1;
  }

 Alarm(DEBUG, "%d %d VAL_Validate_CCS_Description_Message success\n",
	VAR.My_Site_ID, VAR.My_Server_ID );
  
  return 1;
}


/* Determine if a message from the network is valid. */
int32u VAL_Validate_Message( signed_message *message, int32u num_bytes ) {

    byte *content;
    int32u num_content_bytes;

    /* This is a signed message */
    if ( ! VAL_Validate_Signed_Message( message, num_bytes, 1 ) ) {
      Alarm(VALID_PRINT, "Validate signed message failed.\n");
	VALIDATE_FAILURE_LOG(message,num_bytes);
 	return 0;
    }

    if ( num_bytes < sizeof(signed_message) ) {
	/* Safety check -- should be impossible */
	VALIDATE_FAILURE_LOG(message,num_bytes);
	return 0;
    }
    
    content = (byte*)(message + 1);
    num_content_bytes = num_bytes - sizeof(signed_message); /* always >= 0 */

    switch (message->type) {
	case PRE_PREPARE_TYPE:
	    if ( !VAL_Validate_Pre_Prepare( (pre_prepare_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    };

	    UTIL_Purge_Pending_Slot( message );

	    break;
	case PREPARE_TYPE:
	    if ( !VAL_Validate_Prepare( (prepare_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case SIG_SHARE_TYPE:
	    #if 0  /* Should representative combine */
		if ( !UTIL_I_Am_Representative() ) { return 0; }
	    #endif
	    if ( !VAL_Validate_Sig_Share( (sig_share_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break; 
	case PROPOSAL_TYPE:
	    if ( !VAL_Validate_Proposal( (proposal_message*)(content),
		       num_content_bytes, 1 ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case ACCEPT_TYPE:
	    if ( !VAL_Validate_Accept( (accept_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	    if ( !VAL_Validate_Global_View_Change( 
		       (global_view_change_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case SITE_LOCAL_VIEW_PROOF_TYPE:
	    if ( !VAL_Validate_Local_View_Proof( 
		       (local_view_proof_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case UPDATE_TYPE:
	    /* An update is a signed message. Validate the signed message (done
	     * above) and then validate the update structure. */
	    if ( !VAL_Validate_Update( (update_message*)(content),
			num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case L_NEW_REP_TYPE:
	    if ( !VAL_Validate_L_New_Rep( (l_new_rep_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case ORDERED_PROOF_TYPE:
	    if ( !VAL_Validate_Ordered_Proof( (ordered_proof_message*)(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break;
	case LOCAL_RECONCILIATION_TYPE:
	    if ( !VAL_Validate_Local_Reconciliation(
			(local_reconciliation_message*)
			(content),
		       num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break; 
    case GLOBAL_RECONCILIATION_TYPE:
      if (!VAL_Validate_Global_Reconciliation(
			(global_reconciliation_message *)(content), 
			num_content_bytes)) {
	VALIDATE_FAILURE_LOG(message, num_bytes);
	return 0;
      }
      break;
    	case CCS_INVOCATION_TYPE:
	  if ( !VAL_Validate_CCS_Invocation_Message( message, 
						num_content_bytes ) ) {
		VALIDATE_FAILURE_LOG(message,num_bytes);
		return 0;
	    }
	    break; 
    	case CCS_REPORT_TYPE:
      if(!VAL_Validate_CCS_Report_Message((ccs_report_message *)(content),
					 num_content_bytes)) {
	VALIDATE_FAILURE_LOG(message,num_bytes);
	return 0;
      }
      break;
    case CCS_DESCRIPTION_TYPE:
      if(!VAL_Validate_CCS_Description_Message((ccs_description_message *)
					      (content),
					      num_content_bytes)) {
	VALIDATE_FAILURE_LOG(message,num_bytes);
	return 0;
      }
      break;
    case CCS_UNION_TYPE:
      if(!VAL_Validate_CCS_Union_Message(message,
					num_content_bytes, 1)) {
	VALIDATE_FAILURE_LOG(message, num_bytes);
	return 0;
      }
      break;
#if 0
       WE ARE NOT USING QUERIES FOR RED TEAM
    case QUERY_TYPE:
      /*Alarm(DEBUG, "Validating query, always 1 for now.\n");*/
      if(!VAL_Validate_Query_Message((query_message *)(content), 
				     num_content_bytes)) {
	VALIDATE_FAILURE_LOG(message, num_bytes);
	return 0;
      }
      break;
#endif
    default:
	VALIDATE_FAILURE_LOG(message,num_bytes);
	return 0;
    }
   
    /* All tests passed. */
    return 1;
}



