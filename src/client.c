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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include "util/arch.h"
#include "util/alarm.h"
#include "util/sp_events.h"
#include "util/memory.h"
#include "util/data_link.h"

#include "net_types.h"
#include "objects.h"
#include "network.h"
#include "data_structs.h"
#include "utility.h"
#include "timeouts.h"

#include "validate.h"
#include "global_reconciliation.h"

#ifdef	ARCH_PC_WIN95
#include	<winsock.h>
WSADATA		WSAData;
#endif	/* ARCH_PC_WIN95 */

extern network_variables NET;
extern server_variables VAR;

#define MAX_ACTIONS 200000 


/* Client Variables */

int32u My_Client_ID;
int32u My_Site_ID;
int32u update_count;
double total_time;
int32u time_stamp;

/* Local buffers for receiving the packet */
static sys_scatter srv_recv_scat;
static sys_scatter ses_recv_scat;

int32u Current_Query_Replies[NUM_SERVERS_IN_SITE+1];   /* NOTE: Query code is not fully implemented in release version. */
int32u Current_Query_Reply_Count;
int32u query_count;

int32u action_count = 0;

FILE *state_file;
char state_file_name[100];

/* Statics */
static void 	Usage(int argc, char *argv[]);
static void     Init_Memory_Objects(void);

int32u Validate_Message( signed_message *mess, int32u num_bytes ); 
void Init_Network(void); 
void Net_Cli_Recv(channel sk, int dummy, void *dummy_p); 
void Process_Message( signed_message *mess, int32u num_bytes );
void Client_Is_Finished( int32 dummy, void* dummyp ); 
void CLIENT_Init_State_File(); 

void Send_Next_Action();
void Send_Update();
void Send_Query();

void Reset_Query_Data();
double Compute_Average_Latency(void);
void Retransmit_Request( int32 dummy, void* dummyp ); 

util_stopwatch sw;
util_stopwatch latency_sw;
int32u Query_Percentage = 0;

signed_message *pending_update;

double Latencies[MAX_ACTIONS];

/***********************************************************/
/* int main(int argc, char* argv[])                        */
/*                                                         */
/* Main function. Here it all begins...                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* argc, argv: standard, input parameters                  */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

int main(int argc, char* argv[]) 
{

#ifdef ARCH_PC_WIN95
	int ret;
#endif

    Usage(argc, argv);
    Alarm_set(NONE);

#ifdef	ARCH_PC_WIN95    
    ret = WSAStartup( MAKEWORD(1,1), &WSAData );
    if( ret != 0 )
        Alarm( EXIT, "winsock initialization error %d\n", ret );
#endif	/* ARCH_PC_WIN95 */

    NET.program_type = NET_CLIENT_PROGRAM_TYPE;  
    update_count = 0;
    time_stamp = 0;
    total_time = 0;

    E_init(); 
    Init_Memory_Objects();
    Init_Network();

    CLIENT_Init_State_File();

    Reset_Query_Data();
    query_count = 0;

    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys( My_Client_ID, My_Site_ID, RSA_CLIENT ); 
    
    TC_Read_Public_Key(); /* We need to be able to verify site signatures */ 
   
    Alarm(PRINT,"Loading Server Addresses\n"); 
    UTIL_Load_Addresses(); 
    UTIL_Test_Server_Address_Functions(); 

    Send_Next_Action();

    E_queue( Client_Is_Finished, 0, NULL, timeout_client );
    E_queue( Retransmit_Request, 0, NULL, timeout_zero ); 
    
    E_handle_events();

    return(1);
}

/***********************************************************/
/* void Init_Memory_Objects(void)                          */
/*                                                         */
/* Initializes memory                                      */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

static void Init_Memory_Objects(void)
{
    /* initilize memory object types  */
    Mem_init_object_abort(PACK_BODY_OBJ, sizeof(packet), 100, 1);
    Mem_init_object_abort(SYS_SCATTER, sizeof(sys_scatter), 100, 1);
}


/***********************************************************/
/* void Usage(int argc, char* argv[])                      */
/*                                                         */
/* Parses command line parameters                          */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* argc, argv: standard command line parameters            */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

static void    Usage(int argc, char *argv[])
{
    char ip_str[16];
    int i1, i2, i3, i4;
    int tmp;

    /* Setting defaults values */
    NET.My_Address = -1;
    NET.Port = 7100;
    My_Client_ID = 1;

    NET.Mcast_Address = 0;

    while(--argc > 0) {
        argv++;
	if((argc > 1)&&(!strncmp(*argv, "-l", 3))) {
            sscanf(argv[1], "%s", ip_str);
            sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            NET.My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            Alarm(PRINT,"My Address = "IPF"\n",IP(NET.My_Address));
            argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-i", 3))) {
	    sscanf(argv[1], "%d", &tmp);
	    My_Client_ID = tmp;
	    if(My_Client_ID > NUM_CLIENTS || My_Client_ID == 0) {
		Alarm(EXIT, "There are only %d clients in the site. "
		      "Invalid id %d\n",
		      NUM_CLIENTS,
		      My_Client_ID);
	    }
	    argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-s", 3))) {
	    sscanf(argv[1], "%d", &tmp);
	    My_Site_ID = tmp;
	    VAR.My_Site_ID = My_Site_ID;
	    if(My_Site_ID > NUM_SITES || My_Site_ID == 0) {
		Alarm(EXIT, "There can only be %d sites in the system\n"
		      "Invalid id %d\n",
		      My_Site_ID,
		      NUM_SITES);
	    }
	    argc--; argv++;
	} else{
		Alarm(PRINT, "ERR: %d | %s\n", argc, *argv);	
		Alarm(PRINT, "Usage: \n%s\n%s\n%s\n",
		      "\t[-l <IP address>   ] : local address,",
		      "\t[-i <local ID>     ] : local ID, indexed base 1, default is 1"
		      "\t[-s <site  ID>     ] : site  ID, indexed base 1, default is 1"
		);
		Alarm(EXIT, "Bye...\n");
	}
    }

    if(NET.Mcast_Address == 0) {
      NET.Mcast_Address = 225 << 24 | 2 << 16 | 1 << 8 | My_Site_ID;
      Alarm(DEBUG, "%d %d "IPF"\n", My_Site_ID, My_Client_ID, 
	    IP(NET.Mcast_Address));
    }

}

/***********************************************************/
/* void Init_Network(void)                                 */
/*                                                         */
/* First thing that gets called. Initializes the network   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Network(void) 
{
    channel srv_recv_sk;
    /* channel ses_recv_sk*/
    struct hostent  *host_ptr;
    char machine_name[256];
    int rcvbuf_size;

    /* Initialize my IP address */
    
    /* No local address was given in the command line */
    if(NET.My_Address == -1) { 
	gethostname(machine_name, sizeof(machine_name)); 
	host_ptr = gethostbyname(machine_name);
	
	if(host_ptr == NULL)
	    Alarm(EXIT, "Init_My_Node: could not get my ip address "
		  "(my name is %s)\n", machine_name);
	if (host_ptr->h_addrtype != AF_INET)
	    Alarm(EXIT, "Init_My_Node: Sorry, cannot handle addr types"
		  " other than IPv4\n");
	if (host_ptr->h_length != 4)
	    Alarm(EXIT, "Conf_init: Bad IPv4 address length\n");
	
	memcpy(&NET.My_Address, host_ptr->h_addr, sizeof(struct in_addr));
	NET.My_Address = ntohl(NET.My_Address);
	Alarm(PRINT,"My Address = "IPF"\n",IP(NET.My_Address));
    }

    /* Initialize the receiving scatters */
    srv_recv_scat.num_elements = 1;
    srv_recv_scat.elements[0].len = sizeof(packet);
    srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
    if(srv_recv_scat.elements[0].buf == NULL) {
	Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
    }

    ses_recv_scat.num_elements = 1;
    ses_recv_scat.elements[0].len = sizeof(packet);
    ses_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
    if(ses_recv_scat.elements[0].buf == NULL) {
	Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
    }

    /* Initialize the sockets */
    srv_recv_sk = DL_init_channel(RECV_CHANNEL, 
	    NET.Port+2+My_Client_ID+(NUM_SERVERS_IN_SITE * My_Site_ID), 
	    NET.My_Address, 0);
 
    NET.Send_Channel = DL_init_channel(SEND_CHANNEL, NET.Port+1, 0, 0);

    E_attach_fd(srv_recv_sk, READ_FD, Net_Cli_Recv, 0, NULL, MEDIUM_PRIORITY );

    rcvbuf_size = 400000;
    setsockopt( srv_recv_sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(int) );

}

/***********************************************************/
/* void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) */
/*                                                         */
/* Called by the event system to receive data from socket  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* dummy:   not used                                       */
/* dummy_p: not used                                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) 
{
    int	received_bytes;

    received_bytes = DL_recv(sk, &srv_recv_scat);  

    /* Process the packet */
    
    /* 1) Validate the Packet -- Make sure that this is a valid response to a
     * client */
    if ( !Validate_Message( 
		(signed_message*)srv_recv_scat.elements[0].buf, 
		received_bytes) ) {

	Alarm(PRINT,"CLIENT VALIDATION FAILURE\n");
	return;
    }
    /* Now process the message protocol */
    Process_Message( 
		    (signed_message*)(srv_recv_scat.elements[0].buf),  
		    received_bytes);

    /* The following checks to see if the packet has been stored and, if so, it
     * allocates a new packet for the next incoming message. */
    /* Allocate another packet if needed */
    if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
	dec_ref_cnt(srv_recv_scat.elements[0].buf);
	if((srv_recv_scat.elements[0].buf = 
	    (char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	    Alarm(EXIT, "Net_Srv_Recv: Could not allocate packet body obj\n");
	}
    }
}

int32u Validate_Message( signed_message *mess, int32u num_bytes ) 
{

  if(mess->type != COMPLETE_ORDERED_PROOF_TYPE)
    return 0;

  return 1;

}

void Process_Message( signed_message *mess, int32u num_bytes ) 
{
  proposal_message *proposal_specific;
  signed_message   *update;
  update_message   *update_specific;
  signed_message   *ret_proposal;
  int32u caller_is_client;


  /* I should not receive responses if I have no pending update */
  if(pending_update == NULL)
    return;

  /* The response comes in the form of a Complete_Ordered_Proof message.
   * Check the validity of this stuff.  If it matches, it returns a pointer
   * to a proposal (signed_message).  Check it against my pending update, 
   * and if it matches, we're happy. */
  caller_is_client = 1;
  GRECON_Process_Complete_Ordered_Proof(mess, num_bytes, 
					&ret_proposal, caller_is_client);
  
  if(ret_proposal == NULL) {
    /* It must not have checked out properly */
    Alarm(PRINT, "Complete Proof didn't check out.\n");
    return;
  }

  /* Make sure the client id and timestamp match my pending update */
  proposal_specific = (proposal_message *)(ret_proposal + 1);
  update            = (signed_message *)(proposal_specific+1);
  update_specific   = (update_message *)(update+1);

  if(update->machine_id != My_Client_ID)
    return;
      
  if(update->site_id != My_Site_ID)
    return;

  if(update_specific->time_stamp != 
     ((update_message *)(pending_update+1))->time_stamp) {
    Alarm(/*PRINT*/DEBUG, "Timestamp was %d, expecting %d\n", 
	  update_specific->time_stamp, 
	  ((update_message *)(pending_update+1))->time_stamp);
    return;
  }
  
  /* If I get here, I'm happy, move along */
  UTIL_Stopwatch_Stop(&sw);
  total_time += UTIL_Stopwatch_Elapsed(&sw);
      
  update_count++;
  Alarm(DEBUG,"%d %d %d\n", My_Site_ID, My_Client_ID, update_count );

  /* Sanity check */
  if(pending_update == NULL) {
    Alarm(/*EXIT*/DEBUG, "Finished collecting proof, but no pending update!\n");
    return;
  }

  dec_ref_cnt(pending_update);
  pending_update = NULL;
        
  Send_Next_Action();

    
}

void Reset_Query_Data()
{
  int32u i;

  for(i = 0; i <= NUM_SERVERS_IN_SITE; i++)
    Current_Query_Replies[i] = 0;

  Current_Query_Reply_Count = 0;
}

void Send_Next_Action()
{
  int32u choice;

  if(action_count == MAX_ACTIONS) {
    fprintf(stdout, "Finished %d actions, terminating.\n", MAX_ACTIONS);
    exit(0);
  }

  UTIL_Stopwatch_Stop(&latency_sw);
  Latencies[action_count] = UTIL_Stopwatch_Elapsed(&latency_sw);
  Alarm(DEBUG, "Added latency: %f\n", Latencies[action_count]);
  action_count++;

  choice = (int32u) (100.0*rand()/(RAND_MAX+1.0));
  if( choice < Query_Percentage) {
    Send_Query();
  } else { 
    Send_Update();
  }
}

void Send_Update() {

    signed_message *update;
    update_message *update_specific;

    UTIL_Stopwatch_Start(&sw);
    UTIL_Stopwatch_Start(&latency_sw);
  
    update = UTIL_New_Signed_Message();

    update_specific = (update_message*)(update+1);
    
    update->site_id = My_Site_ID;
    update->machine_id = My_Client_ID;
    update->len = sizeof(signed_message) + sizeof(update_message) + 
	200; /* Content, too */
    update->type = UPDATE_TYPE;

    time_stamp++; 
    
    update_specific->time_stamp = time_stamp; /* Time */
    update_specific->address = NET.My_Address;

    /* The content of the update would be copied here. */

    /* Sign the message */
    UTIL_RSA_Sign_Message( update );

    /* Send to all servers, Note: could send to a single server that the client
     * choses */
    UTIL_Site_Broadcast( update );

    pending_update = update;    /* store the update */

    Alarm(PRINT, "Sent update: %d\n", time_stamp);

    E_queue( Retransmit_Request, 0, NULL, timeout_client ); 
 
}

void Retransmit_Request( int32 dummy, void* dummyp ) {

    /* Retransmit the update */
    UTIL_Site_Broadcast( pending_update );
    Alarm(PRINT,"S:%d C:%d Resending %d\n", My_Site_ID, My_Client_ID,
	    time_stamp );
    E_queue( Retransmit_Request, 0, NULL, timeout_client ); 
}

void Client_Is_Finished( int32 dummy, void* dummyp ) {

    /* Exit if the last message was sent a long time ago... */

#if CLIENT_OUTPUT_LATENCY
    char fname[1000];
    FILE *f;
    int32u i;
#endif
    
    double avg_latency; 

    UTIL_Stopwatch_Stop( &sw );

    if ( UTIL_Stopwatch_Elapsed( &sw ) > 180.0 ) {
#if CLIENT_OUTPUT_LATENCY
	/* Create a test file name, open it, write the results, and exit */
	sprintf(fname,"latency.%02d_%02d.log", My_Site_ID, My_Client_ID);
	f = fopen(fname,"w");

	if(action_count > 0) {
	  for(i = 1; i < action_count; i++) {
	    fprintf(f, "%f\n", Latencies[i]);
	  }
	}
	fflush(f);
#endif

      action_count--;
      Alarm(PRINT, "Completed %d actions: %d updates and %d queries\n", 
	    action_count, update_count, query_count);

      avg_latency = Compute_Average_Latency();
      Alarm(PRINT, "The average action latency is: %f\n", avg_latency);

      
      Alarm(EXIT,"Client Exiting Site: %d ID: %d\n",
	    My_Site_ID, My_Client_ID );
    }

    E_queue( Client_Is_Finished, 0, NULL, timeout_client );

}

double Compute_Average_Latency()
{
  int32u i;
  double sum = 0.0;

  Alarm(DEBUG, "Action count in Compute(): %d\n", action_count);

  for(i = 1; i < action_count; i++) {
    if(Latencies[i] > 0.004) {
      Alarm(DEBUG, "High latency for update %d: %f\n", i, Latencies[i]);
    }

    sum += Latencies[i];
  }

  return (sum / (double)(action_count-1));
}


void CLIENT_Init_State_File() {

    int old_timestamp;

    sprintf(state_file_name,"client_state.%02d_%02d.log",
	    My_Site_ID,My_Client_ID);

    state_file = fopen( state_file_name, "r" );

    if ( state_file != NULL ) {
	fscanf( state_file, "%d", &old_timestamp);
	time_stamp = old_timestamp + 10;
	fclose(state_file);
	Alarm(PRINT,"Starting timestamp from state file: %d", time_stamp);
    }

}

/* NOTE: Read query functionality not complete in release version. The query
 * related code in this file was used to test Steward's read query performance.
 * */
void Send_Query() 
{
  signed_message *query;
  query_message  *query_specific;

  UTIL_Stopwatch_Start(&sw);  
  UTIL_Stopwatch_Start(&latency_sw);

  query = UTIL_New_Signed_Message();

  query_specific = (query_message *)(query+1);

  query->site_id    = My_Site_ID;
  query->machine_id = My_Client_ID;
  query->len        = sizeof(signed_message) + sizeof(query_message) + 200;
  query->type       =  QUERY_TYPE;

  query_specific->address    = NET.My_Address;
  query_specific->time_stamp = query_count;

  UTIL_RSA_Sign_Message (query);
  Alarm(DEBUG, "Sent query.\n");

  UTIL_Site_Broadcast(query);
}

//#if 0

//#endif
//
//
//
//
//
//#if 0 
//    if ( My_Site_ID != 1) {
//	Alarm(PRINT,"%d %d %d %d %d\n", My_Site_ID, My_Client_ID, 
//		mess->machine_id, mess->site_id, mess->type );
//    }
//#endif
//
//#if 0
//    if( !VAL_Validate_Message(mess, num_bytes) )
//      return 0;
//#endif
//
//
//#if 0
//    if( mess->type != PROPOSAL_TYPE && mess->type != ACCEPT_TYPE )
//      return 0;
//
//    if( mess->type == PROPOSAL_TYPE ) {
//      /* Make sure I have something pending. */
//      if(pending_update == NULL)
//	return 0;
//
//      /* If I have something pending, make sure the client id and timestamp
//       * match my pending update */
//      proposal_specific = (proposal_message *)(mess+1);
//      update            = (signed_message *)(proposal_specific+1);
//      update_specific   = (update_message *)(update+1);
//
//      if(update->machine_id != My_Client_ID)
//	return 0;
//      
//      if(update->site_id != My_Site_ID)
//	return 0;
//
//      Alarm(PRINT, "In received proposal, Timestamp: %d, Seq: %d\n", 
//	    ((update_message *)(pending_update+1))->time_stamp,
//	    proposal_specific->seq_num);
//
//
//      if(update_specific->time_stamp != 
//	 ((update_message *)(pending_update+1))->time_stamp) {
//	Alarm(PRINT, "Timestamp was %d, expecting %d\n", 
//	      update_specific->time_stamp, 
//	      ((update_message *)(pending_update+1))->time_stamp);
//	return 0;
//      }
//      /* TODO, maybe: compare the updates to be sure they match*/
//    }
//
//    if( mess->type == ACCEPT_TYPE ) {
//      /* To process an Accept, I must already have a Proposal */
//      if(proposal_for_my_update == NULL)
//	return 0;
//      
//      /* If I have a Proposal, this must be for the same seq and view */
//      proposal_specific = (proposal_message *)(proposal_for_my_update+1);
//      accept_specific   = (accept_message *)(mess+1);
//
//      if(accept_specific->global_view != proposal_specific->global_view)
//	return 0;
//
//      if(accept_specific->seq_num != proposal_specific->seq_num)
//	return 0;
//    }
//#endif
//
//#if 0
//      /* Check size */
//    if ( num_bytes != (sizeof(signed_message) + 
//		       sizeof(client_response_message) )) {
//      return 0;
//    }
//
//    if ( mess->len != sizeof(client_response_message) ) {
//      return 0;
//    }
//
//    if ( mess->type != CLIENT_RESPONSE_TYPE &&
//	 mess->type != CLIENT_QUERY_RESPONSE_TYPE) {
//      return 0;
//    }
//    
//    /* Drop any query responses that aren't for the current query */
//    if(mess->type == CLIENT_QUERY_RESPONSE_TYPE) {
//      client_response_message *response_specific = 
//	  (client_response_message*)(mess+1);
//      if(response_specific->time_stamp != query_count) {
//	Alarm(DEBUG, "Dropping query reply: %d %d\n", 
//	      response_specific->time_stamp,
//	      query_count);
//	return 0;
//      }
//    }
//
//    /* Check signature TODO */
//    if ( 0 ) {
//	return 0;
//    }
//#endif 
//	
//    Alarm(DEBUG, "Validated response.\n");
//    return 1;
//    
//}
//
//
//#if 0
//    client_response_message *response_specific;
//    int32u seq;
//
//    response_specific = (client_response_message*)(mess+1);
//
//    if(mess->type == CLIENT_RESPONSE_TYPE) {
//      seq = response_specific->seq_num;
//      update_count++;
//      Alarm(DEBUG,"%d %d %d\n", My_Site_ID, My_Client_ID, update_count );
//      Send_Next_Action();
//    }
//#endif     
//    
//#if 0
//    /* "Responses" will come in the form of a Proposal and an Accept
//     * for my update.  I must have the Proposal first since the Accept
//     * does not contain the update.*/
//    if(mess->type == PROPOSAL_TYPE) {
//
//      if(proposal_for_my_update == NULL) {
//	inc_ref_cnt(mess);
//	proposal_for_my_update = mess;
//      }
//      else {
//	/* If this proposal is from a later view than the one I have, take
//	 * this one instead. */
//	if ( ((proposal_message *)(mess + 1))->global_view > 
//	     ((proposal_message *)(proposal_for_my_update+1))->global_view ) {
//	  dec_ref_cnt(proposal_for_my_update);
//	  inc_ref_cnt(mess);
//	  proposal_for_my_update  = mess;
//	}
//      }
//    }
//     
//    /* Accept only gets here if it matches a proposal that I have.  
//     * Go through and see if I now haveThis means I'm done collecting proof for this pending update. */
//    if(mess->type == ACCEPT_TYPE) {
//
//      /* */
//
//      /* */
//#endif
//
//#if 0
//      UTIL_Stopwatch_Stop(&sw);
//      total_time += UTIL_Stopwatch_Elapsed(&sw);
//      
//      update_count++;
//      Alarm(DEBUG,"%d %d %d\n", My_Site_ID, My_Client_ID, update_count );
//
//      /* Sanity check */
//      if(proposal_for_my_update == NULL)
//	Alarm(EXIT, "Finished collecting proof, but no proposal!\n");
//      
//      dec_ref_cnt(proposal_for_my_update);
//      proposal_for_my_update = NULL;
//
//      /* Sanity check */
//      if(pending_update == NULL) {
//	Alarm(/*EXIT*/DEBUG, "Finished collecting proof, but no pending update!\n");
//	return;
//      }
//
//      dec_ref_cnt(pending_update);
//      pending_update = NULL;
//	
//      Send_Next_Action();
//    }
//#endif
//
//#if 0
//    else if(mess->type == CLIENT_QUERY_RESPONSE_TYPE) {
//      if(Current_Query_Replies[mess->machine_id] == 0) {
//	Current_Query_Replies[mess->machine_id] = 1;
//	Current_Query_Reply_Count++;
//	
//	if(Current_Query_Reply_Count == NUM_FAULTS+1 || 
//		!UTIL_I_Am_In_Leader_Site() ) {
//	  Reset_Query_Data();
//	  query_count++;
//	  Alarm(DEBUG, "Query Complete: %d\n", query_count);
//	  Send_Next_Action();
//	}
//      }
//    }
//#endif

#if 0
	if((argc > 1)&&(!strncmp(*argv, "-l", 2))) {
            sscanf(argv[1], "%s", ip_str);
            sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            NET.My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            Alarm(PRINT,"My Address = "IPF"\n",IP(NET.My_Address));
            argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-p", 2))) {
	    sscanf(argv[1], "%d", &tmp);
	    NET.Port = (int16u)tmp;
	    argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-l", 2))) {
            sscanf(argv[1], "%s", ip_str);
            sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            NET.Mcast_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            Alarm(PRINT,"Multicast Address = "IPF"\n",IP(NET.Mcast_Address));
            argc--; argv++;
	}else
#endif

