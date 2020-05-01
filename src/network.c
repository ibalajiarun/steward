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

#ifndef ARCH_PC_WIN95

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>

#else
#include <winsock.h>
#endif

#include "data_structs.h"
#include "validate.h"
#include "dispatcher.h"
#include "apply.h"
#include "conflict.h"
#include "util/arch.h"
#include "util/alarm.h"
#include "util/sp_events.h"
#include "util/data_link.h"
#include "util/memory.h"

#include "objects.h"
#include "net_types.h"
#include "network.h"
#include "construct_collective_state_protocol.h"
#include "global_reconciliation.h"

#ifdef SET_USE_SPINES
#include "spines/spines_lib.h"
#endif

#define UDP_SOURCE    1
#define SPINES_SOURCE 2

#include "utility.h"
#include "sys/socket.h"


/* Global variables */
extern network_variables NET;
extern server_variables VAR;

extern pending_data_struct PENDING;
extern global_data_struct GLOBAL;

/* Local variables */
/* Local buffers for receiving the packet */
static sys_scatter srv_recv_scat;
static sys_scatter ses_recv_scat;

extern int32 sd;

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
    socklen_t size;

#ifdef SET_USE_SPINES
    channel spines_recv_sk = -1;
    struct sockaddr_in spines_addr, stw_addr;
    int ret;
#endif


    /* Initialize my IP address */
#if 1
    if(NET.My_Address == -1) { /* No local address was given in the command
				  line */
#endif
	gethostname(machine_name,sizeof(machine_name)); 
	host_ptr = gethostbyname(machine_name);
	
	if(host_ptr == NULL)
	    Alarm( EXIT, "Init_My_Node: could not get my ip address"
		   " (my name is %s)\n",
		   machine_name );
	if (host_ptr->h_addrtype != AF_INET)
	    Alarm(EXIT, 
	    "Init_My_Node: Sorry, cannot handle addr types other than IPv4\n");
	if (host_ptr->h_length != 4)
	    Alarm(EXIT, "Conf_init: Bad IPv4 address length\n");
	
        memcpy(&NET.My_Address, host_ptr->h_addr, sizeof(struct in_addr));
	NET.My_Address = ntohl(NET.My_Address);
#if 1
    }
#endif

    if(  (sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
      Alarm(EXIT, "socket error.\n");
   
    Alarm(DEBUG,"SOCKET **** %d\n",sd);

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
    srv_recv_sk = DL_init_channel(RECV_CHANNEL, NET.Port, NET.Mcast_Address, 0);
    NET.Send_Channel = DL_init_channel(SEND_CHANNEL, NET.Port, 0, 0);

    E_attach_fd(srv_recv_sk, READ_FD, Net_Srv_Recv, 
	        UDP_SOURCE, NULL, MEDIUM_PRIORITY );

    getsockopt( srv_recv_sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, &size  );

    Alarm(DEBUG,"Initial receive socket buffer size: %d %d\n", 
	    rcvbuf_size, size );

    rcvbuf_size = 400000;
    setsockopt( srv_recv_sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(int) );

    getsockopt( srv_recv_sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, &size  );

    Alarm(DEBUG,"Buff size set to: %d %d\n", rcvbuf_size, size );

#ifdef SET_USE_SPINES
    spines_addr.sin_family = AF_INET;
    spines_addr.sin_port   = htons(SPINES_PORT);

#if 0
    gethostname(machine_name,sizeof(machine_name)); 
    if((host_ptr = gethostbyname(machine_name)) == NULL) {
	perror("gethostbyname");
	exit(1);
    }    
    memcpy(&spines_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
#endif

    spines_addr.sin_addr.s_addr = htonl(  
        UTIL_Get_Server_Spines_Address( VAR.My_Site_ID, VAR.My_Server_ID )  );

    Alarm(NET_PRINT, "%d %d Init Spines... "IPF"\n",
		VAR.My_Site_ID, VAR.My_Server_ID, 
		IP(ntohl(spines_addr.sin_addr.s_addr) ) );

    spines_recv_sk = spines_socket
	(PF_SPINES, SOCK_DGRAM, 0/*16*/, (struct sockaddr *)&spines_addr);

    if(spines_recv_sk == -1) {
	Alarm(NET_PRINT, "%d %d Could not connect to Spines daemon.\n",
		VAR.My_Site_ID, VAR.My_Server_ID );
    } else { 
	    stw_addr.sin_port = htons(
		    UNIQUE_SPINES_STW_PORT(VAR.My_Site_ID,VAR.My_Server_ID));

	    memcpy(&stw_addr.sin_addr, host_ptr->h_addr, 
		    sizeof(struct in_addr));
	    
	    ret = spines_bind(spines_recv_sk, (struct sockaddr *)&stw_addr,
		    sizeof(struct sockaddr_in));
	    if(ret == -1) {
		printf("Could not bind on Spines daemon.\n");
		exit(1);
	    }

	    E_attach_fd(spines_recv_sk, READ_FD, Net_Srv_Recv, SPINES_SOURCE,
		    NULL, MEDIUM_PRIORITY );

	    NET.Spines_Channel = spines_socket( PF_SPINES, SOCK_DGRAM,
		    16, (struct sockaddr *)&spines_addr );
	    
	    if(NET.Spines_Channel == -1) {
		Alarm(EXIT, "Could not connect to Spines daemon.\n");
	    }

	}
#endif

}

/***********************************************************/
/* void Net_Srv_Recv(channel sk, int dummy, void *dummy_p) */
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

int32u loss_count;

void Net_Srv_Recv(channel sk, int source, void *dummy_p) 
{
    int	received_bytes;
    util_stopwatch w;
    signed_message *mess;
    int32u caller_is_client;
    signed_message *dummy_prop;
    //proposal_message *proposal_specific;


    if(source == UDP_SOURCE) {
	received_bytes = DL_recv(sk, &srv_recv_scat);  
	mess = (signed_message*)srv_recv_scat.elements[0].buf;
    }
#ifdef SET_USE_SPINES
    else if(source == SPINES_SOURCE) {
	received_bytes = spines_recvfrom(sk, srv_recv_scat.elements[0].buf, MAX_PACKET_SIZE, 0, NULL, 0);
	mess = (signed_message*)srv_recv_scat.elements[0].buf;
    }
#endif    
    else {
	return;
    }

    
    /* Process the packet */
    
    mess = (signed_message*)srv_recv_scat.elements[0].buf;


/* TEST */
#if 0 
    if ( mess->type == PREPARE_TYPE ) {
	if ( VAR.My_Server_ID < 3 && PENDING.View < 3 ) {
	    /* For testing -- drop the prepares */
	    return;
	}
    }
#endif

    caller_is_client = 0;
    if ( GRECON_Process_Complete_Ordered_Proof( mess, received_bytes, 
						&dummy_prop, 
						caller_is_client) ) {
	/* The message type was COMPLETE_ORDERED_PROOF */
	return;
    }

    UTIL_Add_To_Mess_Count( mess->type ); 

    /* 1) Validate the Packet */
#if 1 
    UTIL_Stopwatch_Start(&w);
    if ( ! VAL_Validate_Message( 
		(signed_message*)srv_recv_scat.elements[0].buf, 
		received_bytes) ) {
	return;
    }
    UTIL_Stopwatch_Stop(&w);
    Alarm(DEBUG,"%d %d Validate %f\n",VAR.My_Site_ID, VAR.My_Server_ID,
	    UTIL_Stopwatch_Elapsed(&w) ); 
#endif

#if 0 
    if ( mess->type == PROPOSAL_TYPE ) {
	proposal_specific = (proposal_message*)(mess+1);
	if ( proposal_specific->seq_num == 1 ) {
	    loss_count = 0;
	}
	if ( proposal_specific->seq_num == 8 ) {
	    REP_Suggest_New_Local_Representative();
	}
	if ( VAR.My_Server_ID == 2 && proposal_specific->seq_num > 5 && loss_count < 1000 ) {
	    loss_count++;
	    return;
	}
    }
#endif

    /* Process Messages that are needed even if the generate conflicts. */
    DIS_Dispatch_Message_Pre_Conflict_Checking( 
	    (signed_message*)(srv_recv_scat.elements[0].buf) 
	    );

    /* 2) Check for conflicts with our data structure */
     
#if 1    
    if ( CONFL_Check_Message( mess, received_bytes )
	    ) {
	Alarm(NET_PRINT,"CONFLICT FAILED type:%d p.view %d g.view %d site %d server %d con %d  \n", 
		mess->type,
	    PENDING.View, GLOBAL.View, mess->site_id, mess->machine_id,
	    CCS_Am_I_Constrained_In_Pending_Context()
	    );
	
    }  else { 
#endif

	/* No Conflict */

	/* Apply */
	UTIL_Stopwatch_Start(&w);
	APPLY_Message_To_Data_Structs( 
		(signed_message*)(srv_recv_scat.elements[0].buf)
		); 
	UTIL_Stopwatch_Stop(&w);
	if ( mess->type == PREPARE_TYPE ) 
	   Alarm(DEBUG,"%d %d Apply %f\n",VAR.My_Site_ID, VAR.My_Server_ID,
		UTIL_Stopwatch_Elapsed(&w) ); 

	/* Now dispatch the mesage so that is will be processed by the
	 * appropriate protocol */
	UTIL_Stopwatch_Start(&w);
	DIS_Dispatch_Message( 
		(signed_message*)(srv_recv_scat.elements[0].buf) 
		);
	UTIL_Stopwatch_Stop(&w);
	Alarm(DEBUG,"%d %d Dispatch %f\n",VAR.My_Site_ID, VAR.My_Server_ID,
		UTIL_Stopwatch_Elapsed(&w) ); 
    }

    /* The following checks to see if the packet has been stored and, if so, it
     * allocates a new packet for the next incoming message. */
    /* Allocate another packet if needed */
    if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
	dec_ref_cnt(srv_recv_scat.elements[0].buf);
	if ( mess->type == PREPARE_TYPE ) {
	    Alarm(DEBUG,"YES dec_ref_cnt %d\n",mess, 
		    get_ref_cnt(mess) );
	}
	if((srv_recv_scat.elements[0].buf = 
	    (char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	    Alarm(EXIT, "Net_Srv_Recv: Could not allocate packet body obj\n");
	}
    } else {
	if ( mess->type == PREPARE_TYPE ) {
	    Alarm(DEBUG,"NO dec_ref_cnt %d\n",mess, 
		    get_ref_cnt(mess) );
	}
    }
}

