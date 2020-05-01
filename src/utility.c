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

#ifndef ARCH_PC_WIN95

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#else
#include <winsock.h>
#endif

#include "data_structs.h"
#include "utility.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "util/data_link.h"
#include "objects.h"
#include "timeouts.h" 
#include "global_reconciliation.h"
#include <string.h>
#include "stdutil/stddll.h"
#include "network.h"
#include "stdlib.h"

#include "construct_collective_state_protocol.h"
#include "rep_election.h"

#include "apply.h"

#ifdef SET_USE_SPINES
#include "spines/spines_lib.h"
#endif

#define MULTICAST 0

/* The globally accessible variables */

extern server_variables VAR;

extern network_variables NET;

extern global_data_struct GLOBAL;

extern pending_data_struct PENDING;

extern client_data_struct CLIENT;

extern int32 sd;

/* Local */
void UTIL_Multicast( sys_scatter *scat ); 
void UTIL_Load_Spines_Addresses(); 

int32 server_address[NUM_SITES+1][NUM_SERVER_SLOTS]; 
int32 server_address_spines[NUM_SITES+1][NUM_SERVER_SLOTS]; 

#define MAX_MESS_TO_COUNT 100 
int32u mess_count[MAX_MESS_TO_COUNT + 1];

int32u RETRANS_null_add_count;

/* Utility Functions Specific to Steward */

FILE *state_machine_file;

global_slot_struct* UTIL_Get_Global_Slot( int32u seq_num ) {

    global_slot_struct *slot;
    stdit it;
    stdhash *h;

    h = &GLOBAL.History; 

    Alarm(DEBUG,"global seq_num %d\n",seq_num);
    
    stdhash_find( h, &it, &seq_num );

    /* If there is nothing in the slot, then create a slot. */
    if ( stdhash_is_end( h, &it) ) {
	/* Allocate memory for a slot. */
	if((slot = (global_slot_struct*) new_ref_cnt(GLOBAL_SLOT_OBJ))==NULL) {
	    Alarm(EXIT,"DAT_Get_Global_Slot:"
		   " Could not allocate memory for slot.\n");
	}

	/* insert this slot in the hash */
	memset( (void*)slot, 0, sizeof(global_slot_struct) );
	slot->purge_view = GLOBAL.View;
 	stdhash_insert( h, NULL, &seq_num, &slot );
    } else {
	slot = *((global_slot_struct**) stdhash_it_val(&it));
    }	

    return slot;
 
}

pending_slot_struct* UTIL_Get_Pending_Slot( int32u seq_num ) {

    pending_slot_struct *slot;
    stdit it;
    stdhash *h;

    h = &PENDING.History; 

    stdhash_find( h, &it, &seq_num );

    Alarm(DEBUG,"GET PENDING SLOT %d\n",seq_num);

    /* If there is nothing in the slot, then create a slot. */
    if ( stdhash_is_end( h, &it) ) {
	/* Allocate memory for a slot. */
	if((slot = (pending_slot_struct*) new_ref_cnt(PENDING_SLOT_OBJ))==NULL) {
	    Alarm(EXIT,"DAT_Get_Pending_Slot:"
		   " Could not allocate memory for slot.\n");
	}
	memset( (void*)slot, 0, sizeof(pending_slot_struct) );
	slot->purge_view = PENDING.View;
	/* insert this slot in the hash */
 	stdhash_insert( h, NULL, &seq_num, &slot );
    } else {
	slot = *((pending_slot_struct**) stdhash_it_val(&it));
    }	

    return slot;

}

pending_slot_struct* UTIL_Get_Pending_Slot_If_Exists( int32u seq_num ) {

    pending_slot_struct *slot;
    stdit it;
    stdhash *h;

    h = &PENDING.History; 

    stdhash_find( h, &it, &seq_num );

    /* If there is nothing in the slot, then do not create a slot. */
    if ( stdhash_is_end( h, &it) ) {
	/* There is no slot. */
	slot = NULL;
    } else {
	slot = *((pending_slot_struct**) stdhash_it_val(&it));
    }	

    return slot;

}

global_slot_struct* UTIL_Get_Global_Slot_If_Exists( int32u seq_num ) {

    global_slot_struct *slot;
    stdit it;
    stdhash *h;

    h = &GLOBAL.History; 

    stdhash_find( h, &it, &seq_num );

    /* If there is nothing in the slot, then create a slot. */
    if ( stdhash_is_end( h, &it) ) {
	/* There is no slot. */
	slot = NULL;
    } else {
	slot = *((global_slot_struct**) stdhash_it_val(&it));
    }	

    return slot;

}


int UTIL_int_cmp( const void *i1, const void *i2 ) {
    if (*(int*)i1 < *(int*)i2) return -1;
    if (*(int*)i1 > *(int*)i2) return 1;
    return 0;
}

int32u UTIL_hashcode( const void *n ) {
    return *(int*)n;
}

void UTIL_Initialize() {

    int32u mcindex;
    char name[100];

    /* Construct the hashes to store the histories these will store a global
     * slot and a pending slot */
    stdhash_construct( &GLOBAL.History, sizeof(int32u), 
	sizeof(global_slot_struct*), NULL, NULL, 0 ); 

    stdhash_construct( &PENDING.History, sizeof(int32u), 
	sizeof(pending_slot_struct*), NULL, NULL, 0 ); 

    /* INIT memory */

    Mem_init_object_abort(GLOBAL_SLOT_OBJ, sizeof(global_slot_struct), 200, 20);

    Mem_init_object_abort(PENDING_SLOT_OBJ, sizeof(pending_slot_struct), 200,
	    20);

    Mem_init_object_abort(DLL_NODE_OBJ, sizeof(dll_node_struct), 200, 20);


    /* Init counters for messages that are received. */
    for ( mcindex = 0; mcindex < MAX_MESS_TO_COUNT; mcindex++ ) {
	mess_count[mcindex] = 0;
    }

#if OUTPUT_STATE_MACHINE
    /* Open a file for state machine output. */
    sprintf(name,"state_machine_out.%02d_%02d.log",
	    VAR.My_Site_ID,VAR.My_Server_ID);

    state_machine_file = fopen( name, "w" );

    if ( state_machine_file == NULL ) {
	Alarm(PRINT,"Failed to open state machine output file.\n");
    }
#endif

    /* Used for debugging */
    RETRANS_null_add_count = 0;

}

/* Allocate memory for a new signed message */
signed_message* UTIL_New_Signed_Message() {

    signed_message *mess;
    
    if((mess = (signed_message*) new_ref_cnt(PACK_BODY_OBJ))==NULL) {
	Alarm(EXIT,"DAT_New_Signed_Message: Could not allocate memory for message.\n");
    }

    return mess;
}

int32u UTIL_Leader_Site() {
    int32u rep;
    rep = GLOBAL.View % NUM_SITES;
    if ( rep == 0 ) rep = NUM_SITES;
    return rep; 
}

int32u UTIL_Representative() {
    int32u rep;
    rep = PENDING.View % NUM_SERVERS_IN_SITE; 
    if ( rep == 0 ) rep = NUM_SERVERS_IN_SITE;
    return rep; 
}

int32u UTIL_I_Am_In_Leader_Site() {
    if ( VAR.My_Site_ID == UTIL_Leader_Site() ) {
	return 1;
    }
    return 0;
}

int32u UTIL_I_Am_Representative() {
    if ( VAR.My_Server_ID == UTIL_Representative() ) {
	return 1;
    }
    return 0;
}

void UTIL_RSA_Sign_Message( signed_message *mess ) {

    util_stopwatch w;

    UTIL_Stopwatch_Start( &w );
    /* Sign this message */
    OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE, 
	    mess->len + sizeof(signed_message) - SIGNATURE_SIZE, 
	    (byte*)mess ); 
    UTIL_Stopwatch_Stop( &w );
    Alarm(DEBUG,"%d %d Sign %f %d\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, UTIL_Stopwatch_Elapsed( &w ),
	    mess->type );
}

/* Utility functions to send messages. */
void UTIL_Site_Broadcast( signed_message *mess ) {

    /* Broadcast a signed message to all servers in the site. */

    sys_scatter scat;
    signed_message *m;
    int32u sig_share_type;
    int32u seq;
    //accept_message *accept_specific;
    //pre_prepare_message *pre_prepare_specific;

#if 0 
    // BYZ_CODE
    /* Just loose a few packets */
    if ( UTIL_I_Am_Representative() ) {
	if ( rand() % 100 < 10 ) {
	    return;
	}
    }
#endif

#if 0
    // BYZ_CODE 
    // Stop sending pre prepare messages after 5000 updates
    if ( mess->type == PRE_PREPARE_TYPE ) {
	pre_prepare_specific = (pre_prepare_message*)(mess+1);
	if ( pre_prepare_specific->seq_num >= 5000 ) {
	    return;
	}
    }
#endif

#if 0    
       if ( mess->type == ACCEPT_TYPE ) {
	accept_specific = (accept_message*)(mess+1);
	if ( accept_specific->global_view != GLOBAL.View ) {
	    Alarm(EXIT,"SEND %d %d", accept_specific->global_view, GLOBAL.View );
	}
    }
#endif    
 
    seq = 0; 
    sig_share_type = 0;
    if ( mess->type == SIG_SHARE_TYPE ) {
	m = (signed_message*)
	    ((byte*)mess + sizeof(signed_message) + sizeof(sig_share_message));
	sig_share_type = m->type;
	if ( sig_share_type == ACCEPT_TYPE ) {
	    seq = ((accept_message*)(m+1))->seq_num;
	}
    }

    Alarm( DEBUG,"%d %d UTIL_Site_Broadcast mt: %d sig_share_type: %d seq: %d\n",
	VAR.My_Site_ID, VAR.My_Server_ID, mess->type, sig_share_type, seq );

    scat.num_elements = 1;
    scat.elements[0].len = mess->len + sizeof(signed_message);
    scat.elements[0].buf = (char*)mess;
    UTIL_Multicast(&scat);
 
}

/* Send a signed_message to a specific server based on the server's id and the
 * id of the site that the server is in. */
void UTIL_Send_To_Server( signed_message *mess, int32u site_id, int32u server_id ) {

    /* Send a signed message to a server */
   
    sys_scatter scat;
    int32 address;
    int32 ret;

#ifdef SET_USE_SPINES
    struct sockaddr_in dest_addr;
#endif
    
    scat.num_elements = 1;
    scat.elements[0].len = mess->len + sizeof(signed_message);
    scat.elements[0].buf = (char*)mess;

    /* Get address */
   

#ifdef SET_USE_SPINES
    if ( VAR.My_Site_ID != site_id && NET.program_type == 
	    NET_SERVER_PROGRAM_TYPE ) {
	/* Only use spines for servers */
	address = UTIL_Get_Server_Spines_Address( site_id, server_id );

	Alarm(DEBUG,"%d %d SENDING with spines: To %d %d "IPF" port: %d \n",
		VAR.My_Site_ID, VAR.My_Server_ID, site_id, server_id,
		IP(address), UNIQUE_SPINES_STW_PORT(site_id,server_id)
		);

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port   = htons(UNIQUE_SPINES_STW_PORT(site_id,server_id));
	dest_addr.sin_addr.s_addr = htonl(address);

	ret = spines_sendto(NET.Spines_Channel, mess, 
		            mess->len + sizeof(signed_message), 0, 
		(struct sockaddr *)&dest_addr, sizeof(struct sockaddr));
    } else {
	address = UTIL_Get_Server_Address( site_id, server_id );
	ret = DL_send(NET.Send_Channel, address, NET.Port, &scat);
    }
#else
    address = UTIL_Get_Server_Address( site_id, server_id );
    ret = DL_send(NET.Send_Channel, address, NET.Port, &scat);
#endif

    Alarm(DEBUG,"%d %d Sending to "IPF"\n",
	    VAR.My_Site_ID, VAR.My_Server_ID, IP(address));

    if(ret <= 0) {
	Alarm(EXIT, "UTIL_Send_To_Server: socket error\n");
    }
}

void UTIL_Multicast( sys_scatter *scat ) {

    int ret;
#if MULTICAST
#else    
    int32u sindex;
#endif
    
    /* Pseudo Multicast or True Multicast */

#if MULTICAST    
    ret = DL_send(NET.Send_Channel, NET.Mcast_Address, NET.Port, scat);
    if(ret <= 0) {
	Alarm(EXIT, "BFT_Multicast (True multicast): socket error\n");
    }
    Alarm(DEBUG,"%d %d Multicast "IPF"\n",
	    VAR.My_Site_ID,
	    VAR.My_Server_ID, IP(NET.Mcast_Address) );
#else

    Alarm(DEBUG,"PSEUDO MCAST\n");

    for ( sindex = 1; sindex <= NUM_SERVERS_IN_SITE; sindex++) {
        ret = DL_send(NET.Send_Channel, UTIL_Get_Server_Address(VAR.My_Site_ID,sindex), NET.Port, scat);
	if(ret <= 0) {
	    Alarm(EXIT, "BFT_Multicast (Unicast): socket error\n");
	}
	Alarm(DEBUG,"Send to "IPF"\n",IP(UTIL_Get_Server_Address(VAR.My_Site_ID,sindex)) );
    }
#endif    
    
}

/* Load addresses of all servers from a configuration file */

void UTIL_Load_Addresses() {

    /* Open an address.config file and read in the addresses of all servers in
     * all sites. */

    FILE *f;
    char fileName[50];
    char dir[100] = ".";
    int32u num_assigned;
    int32u site, server;
    int32 ip1,ip2,ip3,ip4;
    
    sprintf(fileName,"%s/address.config",dir);

#if 0 
    printf("Opening file: %s\n",fileName);
#endif    

    f = fopen( fileName, "r" );

    if ( f == NULL ) {
	Alarm(EXIT,"   ERROR: Could not open the address file: %s\n", fileName );
    }
 
    /* The file has the following format:
     
    site_id server_id address   

     */

    for ( site = 0; site <= NUM_SITES; site++ ) {
	for ( server = 0; server < NUM_SERVER_SLOTS; server++ ) {
	    server_address[site][server] = 0;
	}
    }
    
    num_assigned = 6;
    
    while ( num_assigned == 6 ) {
	num_assigned = fscanf(f,"%d %d %d.%d.%d.%d",&site,&server,
		&ip1,&ip2,&ip3,&ip4);
	Alarm(DEBUG,"%d %d %d %d %d\n",ip1,ip2,ip3,ip4,num_assigned);
	if ( num_assigned == 6 ) {
	    /* Store the address */
	    server_address[site][server] = 
		( (ip1 << 24 ) | (ip2 << 16) | (ip3 << 8) | ip4 );
	}
    }

#ifdef SET_USE_SPINES
    UTIL_Load_Spines_Addresses();
#endif

}

void UTIL_Load_Spines_Addresses() {

    /* Open an address.config file and read in the addresses of all servers in
     * all sites. */

    FILE *f;
    char fileName[50];
    char dir[100] = ".";
    int32u num_assigned;
    int32u site, server;
    int32 ip1,ip2,ip3,ip4;
   

    /* Note: we are using the same addresses as those in the main
     * address.config file. If different addresses are necessary, two different
     * files can be used. */
    sprintf(fileName,"%s/address.config",dir);
    //sprintf(fileName,"%s/address.config.spines",dir);

#if 1
    printf("Opening file: %s\n",fileName);
#endif    

    f = fopen( fileName, "r" );

    if ( f == NULL ) {
	Alarm(EXIT,"   ERROR: Could not open the address file: %s\n", fileName );
    }
 
    /* The file has the following format:
     
    site_id server_id address   

     */

    for ( site = 0; site <= NUM_SITES; site++ ) {
	for ( server = 0; server < NUM_SERVER_SLOTS; server++ ) {
	    server_address_spines[site][server] = 0;
	}
    }
    
    num_assigned = 6;
    
    while ( num_assigned == 6 ) {
	num_assigned = fscanf(f,"%d %d %d.%d.%d.%d",&site,&server,
		&ip1,&ip2,&ip3,&ip4);
	Alarm(DEBUG,"%d %d %d %d %d\n",ip1,ip2,ip3,ip4,num_assigned);
	if ( num_assigned == 6 ) {
	    /* Store the address */
	    server_address_spines[site][server] = 
		( (ip1 << 24 ) | (ip2 << 16) | (ip3 << 8) | ip4 );
	}
    }
}


int32 UTIL_Get_Server_Address( int32u site, int32u server ) {
    
    if ( site > NUM_SITES || server > NUM_SERVERS_IN_SITE ) {
       return 0;
    }       
	
    return server_address[site][server];
    
}

int32 UTIL_Get_Server_Spines_Address( int32u site, int32u server ) {
    
    if ( site > NUM_SITES || server > NUM_SERVERS_IN_SITE ) {
       return 0;
    }       
	
    return server_address_spines[site][server];
    
}


void UTIL_Test_Server_Address_Functions() {

    /* Assume that the addresses have been loaded. */
    int32u site;
    int32u server;
    int32 address;

    for ( site = 1; site <= NUM_SITES; site++ ) {
	for ( server = 1; server <= NUM_SERVERS_IN_SITE; server++ ) {
	    address = UTIL_Get_Server_Address(site,server);
	    if (address != 0 ) {
		Alarm(DEBUG,"Site: %d Server: %d Address: "IPF"\n",
			site, server, IP(address));
	    }
	}
    }

}

int32u UTIL_Get_ARU(int32u context)
{
  int32u ret = 0;

  if(context == GLOBAL_CONTEXT)
    ret = GLOBAL.ARU;
  else if(context == PENDING_CONTEXT)
    ret = PENDING.ARU;
  else
    Alarm(DEBUG, "UTIL_Get_ARU: Unexpected context.\n");

  return ret;
}

int32u UTIL_Get_View(int32u context)
{
  int32u ret = 0;

  if(context == GLOBAL_CONTEXT)
    ret = GLOBAL.View;
  else if(context == PENDING_CONTEXT)
    ret = PENDING.View;
  else
    Alarm(DEBUG, "UTIL_Get_View: Unexpected context.\n");

  return ret;
}

void UTIL_Send_To_Site_Representatives( signed_message *mess ) {

    int32u nsite;
    accept_message *accept_specific;

    if ( mess == NULL ) {
	return;
    }

    Alarm( DEBUG, "%d %d Send to site rep %d %d\n", 
	VAR.My_Site_ID, VAR.My_Server_ID, mess->len + 
	(int32u)(sizeof(signed_message)),
        mess->type );

    if ( mess->type == ACCEPT_TYPE ) {
	accept_specific = (accept_message*)(mess+1);
	if ( accept_specific->global_view != GLOBAL.View ) {
	    Alarm(DEBUG,"Sending accept not equal to my view: %d %d",
		    accept_specific->global_view, GLOBAL.View );
	}
    }

    for (nsite = 1; nsite <= NUM_SITES; nsite++ ) {
	if ( nsite != VAR.My_Site_ID  ) {
	    /* Send to the server that I currently think is the representative
	     * for this site. */
	    UTIL_Send_To_Server( mess, nsite, 
		    UTIL_Get_Site_Representative(nsite) );
	}
    }

}

int32u UTIL_Get_Site_Representative( int32u site_id ) {

    /* Get the site representative for a particular server. If we do not know
     * who the site rep is, we return 1 for now. It may be better to handle
     * this in a different way. */
 
    signed_message *local_view_proof;
    int32u lview;
    int32u rep;

    local_view_proof = PENDING.Local_view_proof[ site_id ];

    if ( local_view_proof == NULL ) {
	/* Default to 1 - this prevents any possiblities of core dumps.
	 * However, it may be good to specifically handle situations where we
	 * do not know the site rep. */
	return 1;
    }
    lview = REP_Get_View_From_Proof( local_view_proof ); 
    rep = lview % NUM_SERVERS_IN_SITE;
    if ( rep == 0 ) rep = NUM_SERVERS_IN_SITE;
    Alarm(DEBUG,"UTIL_Get_Site_Representative site: %d v:%d rep:%d",
	    site_id,lview,rep);
    return rep;

}

void UTIL_Send_To_Site_Servers_With_My_ID(signed_message *mess)
{
    /* Send this message to the server that has the same id as mine at every
     * site. This can be used to pass messages reliably between sites.
     * Consider two sites, s1 and s2. If all servers in s1 send a message to
     * the server in s2 with the same id, then some messages will go through.
     * THIS WORKS only if the receiving servers in S2 forward the message that
     * the recieve to all servers in their site. */

    int32u si;

    if ( mess == NULL ) {
	/* Nothing to send */
	return;
    }

    for ( si = 1; si <= NUM_SITES; si++ ) {
	UTIL_Send_To_Server( mess, si, VAR.My_Server_ID );
    }

}

void UTIL_Send_To_Client( int32 address, int32u site, int32u id, signed_message *mess ) {

    sys_scatter scat;
    int32 ret;
    struct sockaddr_in cli_addr;
    socklen_t len;

    bzero(&cli_addr, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port   = htons(NET.Port+2+id+(site*NUM_SERVERS_IN_SITE));
    cli_addr.sin_addr.s_addr = htonl(address);

    scat.num_elements = 1;
    scat.elements[0].len = mess->len + sizeof(signed_message);
    scat.elements[0].buf = (char*)mess;

    if ( !UTIL_I_Am_In_Leader_Site() ) {
    Alarm(DEBUG,"Sending to "IPF" seq: %d\n",
	    IP(address),((client_response_message*)(mess+1))->seq_num);
    }
   
    len = sizeof(struct sockaddr);

    Alarm(DEBUG,">>>>>>>>>>>> "IPF" %d p:%d %d l:%d %d\n",IP(address),
	    cli_addr.sin_addr.s_addr, 
	    NET.Port+2+id+(site*NUM_SERVERS_IN_SITE), 
	    cli_addr.sin_port,
	    mess->len+sizeof(signed_message),
	    len );

    Alarm(DEBUG,"SOCKET: %d\n",sd);
    ret = sendto(sd, (char *)mess, mess->len+sizeof(signed_message), 0, 
		 (struct sockaddr *)&cli_addr, len);
    if(ret < 0) {
	perror("xxxxx");
      Alarm(EXIT, "Sendto error.\n");
    }

#if 0
    ret = DL_send(NET.Send_Channel, address, 
	    NET.Port+2+id+(site*NUM_SERVERS_IN_SITE), &scat);
    if(ret <= 0) {
	Alarm(EXIT, "UTIL_Send_To_Client: socket error\n");
    }
#endif  
}

void UTIL_Stopwatch_Start( util_stopwatch *stopwatch ) {
    stopwatch->start = E_get_time();
}

void UTIL_Stopwatch_Stop( util_stopwatch *stopwatch ) {
    stopwatch->stop = E_get_time();
}

double UTIL_Stopwatch_Elapsed( util_stopwatch *stopwatch ) {
    sp_time result;
    double elapsed;
    result = E_sub_time(stopwatch->stop, stopwatch->start);
    elapsed = (double)result.sec + (double)(result.usec) / 1000000.0;
    return elapsed;
}

/* Retransmission Utility */
void UTIL_RETRANS_Construct( retrans_struct *retrans ) {

    Alarm(DEBUG,"Construct retrans\n"); 
    
    UTIL_DLL_Clear( &(retrans->dll) );
    retrans->is_started = 0;

    /* Public, user specified flags and variables. Defaults: */
    retrans->repeat = 0;
    retrans->inter_message_time = timeout_zero;
    retrans->inter_group_time = timeout_zero;
    
    retrans->dest_site_id = VAR.My_Site_ID;
    retrans->dest_server_id = 0;

    retrans->type = UTIL_RETRANS_DEFAULT;

}



void UTIL_RETRANS_Add_Message( retrans_struct *retrans, signed_message *message
	) {
  
    if ( message == NULL ) {
	RETRANS_null_add_count++;
	Alarm(RETRANS_PRINT,"UTIL_RETRANS_Add_Message: TRIED TO ADD NULL %d\n",
		RETRANS_null_add_count );
	/*if ( RETRANS_null_add_count == 237 ) {
	    Alarm(EXIT,"XXXX\n");
	}*/
	return;
    }

    //inc_ref_cnt(message);

    UTIL_DLL_Add_Data( &(retrans->dll), message );
    
    Alarm(RETRANS_PRINT,"UTIL_RETRANS_Add_Message t%d mess:%d m.type %d m.site"
	    " %d m.id %d\n",
	    retrans->type, message, 
	    message->type, message->site_id, message->machine_id );

}

void UTIL_RETRANS_Clear( retrans_struct *retrans ) {

    /* Go through all messages in list and decrement the ref counter, then
     * delete entries in the list. */

    retrans->is_started = 0;

    UTIL_DLL_Clear( &(retrans->dll) );

    E_dequeue( UTIL_RETRANS_Send_Next, 0, retrans );
 
}

void UTIL_RETRANS_Start( retrans_struct *retrans ) {
    /* Start Sending */    
    
    if ( retrans->is_started ) return;
    
    UTIL_DLL_Set_Begin(&(retrans->dll));

    retrans->is_started = 1;
    
    Alarm(DEBUG,"UTIL_RETRANS_Start t%d: %d\n", 
	  retrans->type, UTIL_DLL_Get_Signed_Message(&(retrans->dll)) );
    
    /* Schedule */
    E_queue( UTIL_RETRANS_Send_Next, 0, retrans, 
		 retrans->inter_message_time );
 
}

void UTIL_RETRANS_Send_Next( int dummy, void *retrans_data ) {

    retrans_struct *retrans;
    signed_message *mess;

    retrans = (retrans_struct*)(retrans_data);

    if ( UTIL_DLL_At_End( &(retrans->dll) ) ) {
	/* the position is at the end -- we either repeat or stop */
	if ( retrans->repeat && retrans->is_started ) {
	    /* Set the iterator to the beginning */
	    UTIL_DLL_Set_Begin(&(retrans->dll));
 	    /* Schedule the function to be called again */
	    E_queue( UTIL_RETRANS_Send_Next, 0, retrans,
		    retrans->inter_group_time );
	    Alarm(RETRANS_PRINT,"RETRANS t%d: At END\n",retrans->type);
	    return;
	} else {
	    /* Stop -- clear */
	    UTIL_RETRANS_Clear( retrans );
	    return;
	}
    }

    mess = UTIL_DLL_Get_Signed_Message( &(retrans->dll) );

    /*
    Alarm(PRINT,"%d %d %d %d\n",
	    retrans->inter_message_time.sec,retrans->inter_message_time.usec,
	    retrans->repeat, mess );
    */

    Alarm(DEBUG,"RETRANS Send %d\n",mess);
 
    /* Send the mess */
    if ( retrans->type == UTIL_RETRANS_TO_SERVERS_WITH_MY_ID ) {
	Alarm(RETRANS_PRINT,"RETRANS To servers with my id: %d type %d\n", 
	       VAR.My_Server_ID,
	       mess->type);
	UTIL_Send_To_Site_Servers_With_My_ID(mess);
    } else if ( retrans->type == UTIL_RETRANS_TO_LEADER_SITE_REP ) {
	Alarm(RETRANS_PRINT,"RETRANS To leader site rep (%d,%d) type %d\n",
	       UTIL_Leader_Site(),
	       UTIL_Representative(),
	       mess->type);
	UTIL_Send_To_Server( mess, UTIL_Leader_Site(), 
		UTIL_Representative() );
    } else if ( retrans->dest_site_id == 0 ||
	        retrans->dest_server_id == 0 ) {
	Alarm(RETRANS_PRINT,"RETRANS Broadcast: type %d\n", mess->type);
	UTIL_Site_Broadcast( mess );
    } else {
	Alarm(RETRANS_PRINT,"RETRANS To server site:%d server: %d : type %d\n", 
	       retrans->dest_site_id, retrans->dest_server_id,
	       mess->type);
	UTIL_Send_To_Server( mess, 
		retrans->dest_site_id, retrans->dest_server_id );
    } 
    /* Go to the next message */
    UTIL_DLL_Next( &(retrans->dll) );
    E_queue( UTIL_RETRANS_Send_Next, 0, retrans,
		    retrans->inter_message_time );
 
}

/* DLL funtions */

void UTIL_DLL_Clear( dll_struct *dll ) {
    dll_node_struct *next;
    dll_node_struct *current;
    next = dll->begin;
    while ( next != NULL ) {
	current = next;
	next = next->next;
	dec_ref_cnt(current->data);
	dec_ref_cnt(current);
    }
    dll->current_position = NULL;
    dll->begin = NULL;
    dll->end = NULL;
}

void UTIL_DLL_Next( dll_struct *dll ) {
    if ( dll->current_position == NULL )
	return;
    dll->current_position = 
	((dll_node_struct*)(dll->current_position))->next;
}

int32u UTIL_DLL_At_End( dll_struct *dll ) {
    if ( dll->current_position == NULL ) {
	return 1;
    }
    return 0;
}

void UTIL_DLL_Set_Begin( dll_struct *dll ) {
    dll->current_position = dll->begin;
}

signed_message* UTIL_DLL_Get_Signed_Message( dll_struct *dll ) {
    if ( dll->current_position == NULL ) return NULL;
    return (signed_message*)dll->current_position->data;
}

int32u UTIL_DLL_Is_Empty( dll_struct *dll ) {
    if ( dll->begin == NULL ) {
	return 1;
    }
    return 0;
}

signed_message* UTIL_DLL_Front_Message( dll_struct *dll ) {
    if ( dll->begin == NULL ) return NULL;
    return (signed_message*)(dll->begin->data);
}

void UTIL_DLL_Pop_Front( dll_struct *dll ) {
    dll_node_struct *begin;
    if  ( dll->begin != NULL ) {
	/* adjust position if necessary */
	if (dll->current_position == dll->begin) {
	    dll->current_position = dll->begin->next;
	}
	if (dll->end == dll->begin ) {
	    dll->end = NULL;
	}
	if ( dll->begin->data != NULL ) {
	    dec_ref_cnt(dll->begin->data);
	    dll->begin->data = NULL;
	}
	begin = dll->begin->next;
	dec_ref_cnt(dll->begin);
	dll->begin = begin; 
    }
}

void UTIL_DLL_Set_Last_Int32u_1( dll_struct *dll, int32u val ) {
    if (dll->end != NULL) {
	dll->end->int32u_1 = val;
    }
}

int32u UTIL_DLL_Front_Int32u_1( dll_struct *dll ) {
    if ( dll->begin == NULL ) { return 0; }
    return (dll->begin->int32u_1);
}

void UTIL_DLL_Add_Data( dll_struct *dll, void *data ) {

    inc_ref_cnt( data );

    dll_node_struct *node;
 
    if((node = (dll_node_struct*)new_ref_cnt(DLL_NODE_OBJ))==NULL) {
	Alarm(EXIT,"UTIL_DLL_Add_Data:"
	     " Could not allocate memory for slot.\n");
    }

    if ( dll->end != NULL ) {
	dll->end->next = node;
    }
 
    if ( dll->begin == NULL ) {
	dll->begin = node;
    }
 
    node->data = data;
    node->next = NULL;
    node->int32u_1 = 0;
    dll->end = node;

}

int32u UTIL_Is_Globally_Ordered( int32u seq_num ) {

    global_slot_struct *slot;
    
    slot = UTIL_Get_Global_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return 0;
    }

    return slot->is_ordered;
 
}

int32u UTIL_Is_Pending_Proposal_Ordered( int32u seq_num ) {

    pending_slot_struct *slot;
    
    slot = UTIL_Get_Pending_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return 0;
    }
    
    if ( slot->proposal != NULL ) {
	return 1;
    }
    return 0; 

}

util_stopwatch busy_wait_stopwatch;

/* Do a busy wait for emulation purposes. */
void UTIL_Busy_Wait( double sec ) {

    UTIL_Stopwatch_Start(&busy_wait_stopwatch); 

    UTIL_Stopwatch_Stop(&busy_wait_stopwatch); 

    while  (UTIL_Stopwatch_Elapsed(&busy_wait_stopwatch) < sec ) {
	UTIL_Stopwatch_Stop(&busy_wait_stopwatch); 
    }
    
}

int32u UTIL_Number_Of_Clients_Seen() {

    /* Iterate over the client array and count the number of slots that have a
     * pending time_stamp greater than 0 */

    int32u cli_index, site_index;
    int32u count;

    count = 0;

    for ( site_index = 1; site_index <= NUM_SITES; site_index++ ) {
	for ( cli_index = 1; cli_index <= NUM_CLIENTS; cli_index++ ) {
	    if ( CLIENT.client[site_index][cli_index].pending_time_stamp > 0 ) {
		count++;
	    }
	}
    }
    
    return count;

}

void UTIL_Dump_Mess_Count() {
#if 0
    int i;
    Alarm(PRINT,"Message Counts:\n");
    for ( i = 0; i <= MAX_MESS_TO_COUNT; i++ ) {
	if ( mess_count[i] > 0 ) {
	    Alarm(PRINT," %d %d type: %d count: %d\n", 
		    VAR.My_Site_ID, VAR.My_Server_ID, i, mess_count[i] );
	}
    }
#endif
}

void UTIL_Add_To_Mess_Count( int32u type ) {

    if ( type <= MAX_MESS_TO_COUNT ) {
	mess_count[type]++;
    }
}


/* CCS Utilities for functions external */

extern ccs_state_struct             CCS_STATE;

void UTIL_Update_CCS_STATE_PENDING( int32u seq_num ) {
    if ( seq_num > CCS_STATE.My_Max_Seq_Response[PENDING_CONTEXT]) {
	CCS_STATE.My_Max_Seq_Response[PENDING_CONTEXT] = seq_num;	
    }
}

void UTIL_Update_CCS_STATE_GLOBAL( int32u seq_num ) {
    if ( seq_num > CCS_STATE.My_Max_Seq_Response[GLOBAL_CONTEXT]) {
	CCS_STATE.My_Max_Seq_Response[GLOBAL_CONTEXT] = seq_num;	
    }
}

/* Apply an update to the state machine */
void UTIL_Apply_Update_To_State_Machine( signed_message *proposal ) {

#if OUTPUT_STATE_MACHINE
    /* Write the data in the proposal to a file: */
    signed_message *update;
    proposal_message *proposal_specific;
    update_message *update_specific;
    char *content;

    /* Check that the message is a proposal */
    if ( proposal->type != PROPOSAL_TYPE ) {
	Alarm(PRINT,
	 "\n\n**** WARNING: tried to write incompatible message ***\n\n" );
    }

    proposal_specific = (proposal_message*)(proposal+1);
    update = (signed_message*)(proposal_specific+1);
    update_specific = (update_message*)(update+1);
    content = (char*)(update_specific+1);

    /* Print small message to the file. */
    fprintf(state_machine_file,"%d cli:%d site:%d time_stamp:%d\n",
	    proposal_specific->seq_num,   /* The global sequence number */
	    update->machine_id,           /* The id of the client */
	    update->site_id,              /* The site of the client */
	    update_specific->time_stamp   /* The time stamp of client */
	    /*content */                  /* some data */
	    );

    //fflush(0);

#endif
}

/* CLIENT */

void CLI_ERR( char *text ) {

    Alarm(DEBUG,"%d %d CLI_ERR: %s\n",
	   VAR.My_Site_ID, VAR.My_Server_ID, text );

}

/* This function is called by servers that process updates coming from clients.
 * If a client sends an update and I know it was globally ordered I
 * respond to this client -- the response function only sends a message to the
 * client if I am the site representative of the site to which the client
 * belongs. If I am the rep at leader site, I should try to play the update. */
int32u UTIL_CLIENT_Process_Update( signed_message *update ) {

    /* If I can inject the update */

    update_message *update_specific;
    int32u cli_id;
    int32u cli_ts;
    int32u cli_site;
    global_slot_struct *gs;

    update_specific = (update_message*)(update+1);

    cli_id = update->machine_id;
    cli_site = update->site_id;
    cli_ts = update_specific->time_stamp;

    if ( cli_site > 0 ) 
       Alarm(DEBUG,"gts %d pts %d\n",
		CLIENT.client[ cli_site ][ cli_id ].globally_ordered_time_stamp,
		CLIENT.client[ cli_site ][ cli_id ].pending_time_stamp);

    /* I should respond to the client if the update sequence number matches the
     * global one. Otherwise it's a replay attack. */
    if ( cli_ts == 
	   CLIENT.client[ cli_site ][ cli_id ].globally_ordered_time_stamp ) {
	Alarm(DEBUG,"Sending a response to a client because I already ordered "
	        "it. seq:%d cli_ts:%d\n",
		CLIENT.client[cli_site][cli_id].global_seq_num,
		cli_ts );
    	if ( 1 ) { 
	    UTIL_CLIENT_Respond_To_Client( update, 
		CLIENT.client[ cli_site ][ cli_id ].global_seq_num );
	} 
       	if ( cli_site != VAR.My_Site_ID ) {
	    GRECON_Send_Response( CLIENT.client[cli_site][cli_id]
		    .global_seq_num, cli_site,
		    UTIL_Get_Site_Representative(cli_site) ); 
	}
	/* Sanity check: The update that we are processing should match the
	 * update that the client sent unless under attack. */
	
	gs = UTIL_Get_Global_Slot_If_Exists(
	       CLIENT.client[ cli_site ][ cli_id ].global_seq_num );

	if ( gs == NULL ) {
	    CLI_ERR("Global slot NULL");
	}

	if ( !gs->is_ordered ) {
	    CLI_ERR("Global slot not ordered.");
	}

	if ( gs->proposal == NULL ) {
	    CLI_ERR("Proposal NULL");
	}

	if ( memcmp( 
		    update,
		    ((byte*)(gs->proposal+1))+(sizeof(proposal_message)),
		    update->len + sizeof(signed_message)
		    ) != 0 ) {
	    CLI_ERR("Updates don't match");
	}
	/* I don't need to forward the update, I don't need to inject it, I'm
	 * finished. */
	return 0;
    }
    
    if ( UTIL_I_Am_Representative() &&
         UTIL_I_Am_In_Leader_Site() ) {
	if ( cli_ts > 
	     CLIENT.client[ cli_site ][ cli_id ].pending_time_stamp ) {
	    /* Replace: We can inject update */
	    CLIENT.client[ cli_site ][ cli_id ].pending_time_stamp = 
		cli_ts;
	    Alarm(DEBUG,"CLIENT_UTIL Accepting update\n");
	    return 1;
	} else {
	    Alarm(DEBUG,"CLIENT_UTIL Rejecting update\n");
	    return 0;  /* FINAL -- was 1 */
	}
    }

    if ( !UTIL_I_Am_In_Leader_Site() && cli_ts >
	    CLIENT.client[ cli_site ][ cli_id ].globally_ordered_time_stamp 
	    && VAR.My_Site_ID == update->site_id ) {
	/* We have not globally ordered this update, so forward it to the
	 * representative of the leader site. */
	if ( update->site_id != 1 )
		Alarm(DEBUG,"Forwarding update to Site %d, Server %d\n",
			UTIL_Leader_Site(), 
			UTIL_Get_Site_Representative(UTIL_Leader_Site()) );
	UTIL_Send_To_Server( update, UTIL_Leader_Site(), 
		UTIL_Get_Site_Representative(UTIL_Leader_Site()) );
	return 0;
    }

    return 0;

}

void UTIL_CLIENT_Process_Globally_Ordered_Proposal( signed_message *proposal ) {

    /* WE ASSUME THE PROPOSAL is globally ordered. */

    proposal_message *proposal_specific;
    signed_message *update;
    update_message *update_specific;
    int32u cli_id;
    int32u cli_ts;
    int32u cli_site;

    if ( proposal == NULL ) {
	Alarm(DEBUG,"UTIL_CLIENT_Process_Globally_Ordered_Proposal: "
		"CALLED WITH NULL\n");
	return;
    }

    proposal_specific = (proposal_message*)(proposal+1);
    
    update = (signed_message*)(proposal_specific + 1);
    update_specific = (update_message*)(update+1);

    cli_id = update->machine_id;
    cli_site = update->site_id;
    cli_ts = update_specific->time_stamp;

    if ( update_specific->time_stamp > 
	 CLIENT.client[ cli_site ][ cli_id ].globally_ordered_time_stamp ) {
	/* Replace */
	CLIENT.client[ cli_site ][ cli_id ].globally_ordered_time_stamp = 
	    update_specific->time_stamp;
	CLIENT.client[ cli_site ][ cli_id ].global_seq_num = 
	    proposal_specific->seq_num;
    }

}

void UTIL_CLIENT_Respond_To_Client(signed_message *update, int32u seq_num)
{
  update_message *update_specific;
  signed_message *ordered_proof;
#if 0
  global_slot_struct *g_slot;
  int32u send_count, i;
#endif

  update_specific = (update_message *)(update + 1);

  /* See if I've globally ordered this sequence number.  If so, then I want
   * to send back a reply to the client if I'm the representative of the 
   * client's site */

  Alarm(U_PRINT,"Trying to RESPOND to client for seq num %d\n",seq_num);  

  if( !UTIL_Is_Globally_Ordered(seq_num) ) {
    Alarm(U_PRINT,"RESPOND: not globally ordered\n");
    return;
  }
 
  if ( !UTIL_I_Am_Representative() 
       || VAR.My_Site_ID != update->site_id ) {   
    Alarm(U_PRINT,"RESPOND: not rep or from my site client site id %d\n",
	  update->site_id);
    return;
  }                                                    
              
  Alarm(PRINT, "----Sending response to client site %d, id %d "
	"for seq %d "IPF"\n", 
	update->site_id, update->machine_id, seq_num, 
	IP(update_specific->address) );

  ordered_proof = GRECON_Construct_Ordered_Proof_Message( seq_num );  

  UTIL_Send_To_Client( update_specific->address, update->site_id, 
  		       update->machine_id, ordered_proof );
  
  /* We're done with the message */
  dec_ref_cnt(ordered_proof); 
     
#if 0 
  /* This is the old way of replying to the client: send it the
   * Proposal and a majority of accepts.  We now bundle them together
   * and assume that it all fits into a single physical message. */

  /* NOTE: This slot must exist since it is globally ordered */
  g_slot = UTIL_Get_Global_Slot(seq_num);

  UTIL_Send_To_Client( update_specific->address, update->site_id,             
  		       update->machine_id, g_slot->proposal ); 

  send_count = 0;                                                             
  for(i = 1; i <= NUM_SITES; i++) {                                           
    if(g_slot->accept[i] != NULL) { 
      UTIL_Send_To_Client( update_specific->address, update->site_id,         
			   update->machine_id, g_slot->accept[i] );
      send_count++; 
      
      if(send_count == (NUM_SITES / 2) )                                      
	break;                                                                
    }
  }
#endif
  
}

void UTIL_CLIENT_Reset_On_View_Change() {

    int32u site;
    int32u id;

    for ( site = 1; site <= NUM_SITES; site++ ) {
	for ( id = 1; id <= NUM_CLIENTS; id++ ) {
	    CLIENT.client[site][id].pending_time_stamp = 
		CLIENT.client[site][id].globally_ordered_time_stamp;
	}
    }


}

void UTIL_PURGE( signed_message **m ) {
    
    if ( *m != NULL ) {
	dec_ref_cnt(*m);
	*m = NULL;
    }

}

void UTIL_Purge_Pending_Slot( signed_message *pre_prepare ) {
    
    pre_prepare_message *pre_prepare_specific;

    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);

    UTIL_Purge_Pending_Slot_Seq( pre_prepare_specific->seq_num );

};


void UTIL_Purge_Pending_Slot_Seq( int32u seq_num ) {

    pre_prepare_message *pre_prepare_specific;
    pending_slot_struct *slot;
    int32u si;
    proposal_message *proposal_specific;

    /* Get slot */
    slot = UTIL_Get_Pending_Slot_If_Exists( seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( slot->proposal != NULL ) {
	/* Always get rid of proposals from old views */
	proposal_specific = (proposal_message*)(slot->proposal + 1);
	if ( proposal_specific->global_view != GLOBAL.View ) {
	    UTIL_PURGE( &slot->proposal );
	}
    }

    if ( slot->prepare_certificate.pre_prepare != NULL ) {
	/* Always get rid of prepare certificates from old views */
	pre_prepare_specific = (pre_prepare_message*)
	    (slot->prepare_certificate.pre_prepare + 1);
	if ( pre_prepare_specific->global_view != GLOBAL.View ) {
	    UTIL_PURGE( &slot->prepare_certificate.pre_prepare );
	}
	for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	    UTIL_PURGE( &slot->prepare_certificate.prepare[si] );
	}
    }

    if ( slot->purge_view == PENDING.View ) {
	/* We already purged this slot */
	return;
    }

    /* We purged the slot in this view */
    slot->purge_view = PENDING.View; 

    /* PURGE */
    UTIL_PURGE( &slot->pre_prepare );

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
	UTIL_PURGE( &slot->prepare[si] );
	UTIL_PURGE( &slot->sig_share[si] );
    }

}

void UTIL_Purge_Global_Slot( signed_message *proposal ) {

    signed_message   *accept;
    accept_message   *accept_specific;
    proposal_message *proposal_specific;
    global_slot_struct *slot;
    int32u si;

    proposal_specific = (proposal_message*)(proposal+1);
 
    /* Get slot */
    slot = UTIL_Get_Global_Slot_If_Exists( proposal_specific->seq_num );

    if ( slot == NULL ) {
	return;
    }

    if ( slot->purge_view == GLOBAL.View ) {
	/* We already purged this slot */
	return;
    }

    /* PURGE */

    /* We purged the slot in this view */
    slot->purge_view = GLOBAL.View; 

    for ( si = 1; si <= NUM_SERVERS_IN_SITE; si++ ) {
      accept = APPLY_Get_Content_Message_From_Sig_Share(
						       slot->accept_share[si]);

      if(accept != NULL) {
	accept_specific = (accept_message *)(accept+1);

	if( accept_specific->global_view != GLOBAL.View )
	  UTIL_PURGE( &(slot->accept_share[si]) );
      }
    }
   
    slot->time_accept_share_sent = E_get_time();

    /* WE ONLY PURGE THE PROPOSAL AND ACCEPTS IF THE SLOT IS NOT GLOBALLY
     * ORDERD */

    if ( slot->is_ordered ) {
	return;
    }

    /* If the proposal exists and is not from my global view, purge it. */
    if(slot->proposal != NULL) {
      proposal_specific = (proposal_message *)(slot->proposal + 1);
      if(proposal_specific->global_view != GLOBAL.View)
	UTIL_PURGE( &slot->proposal );
    }
    
    /* If any accepts exist that aren't from my global view, purge them */
    for ( si = 1; si <= NUM_SITES; si++ ) {
      if(slot->accept[si] != NULL) {
	accept_specific = (accept_message *)(slot->accept[si] + 1);

	if(accept_specific->global_view != GLOBAL.View)
	  UTIL_PURGE( &slot->accept[si] );
      }
    }
}

/* ATTACK */

int32u UTIL_ATTACK_Len( int32u type ) {

    switch (type) {
	case PREPARE_TYPE: 
	    return sizeof(signed_message) + sizeof(prepare_message);
	case PRE_PREPARE_TYPE:
	    return sizeof(signed_message) * 2+ sizeof(pre_prepare_message)
		   + sizeof( update_message ) + 200;
	case SIG_SHARE_TYPE:
	    return sizeof(signed_message) + sizeof(sig_share_message) + 500; 
	case PROPOSAL_TYPE: 
	    return sizeof(signed_message) * 2 + sizeof(proposal_message) +
		sizeof( update_message ) + 200;
	case ACCEPT_TYPE: 
	    return sizeof(signed_message) + sizeof(accept_message); 
	case UPDATE_TYPE:
	    return sizeof(signed_message) + sizeof(update_message) + 200; 
	case L_NEW_REP_TYPE:
	    return sizeof(signed_message) + sizeof(l_new_rep_message) + 200; 
	case ORDERED_PROOF_TYPE: 
	    return sizeof(signed_message) * 2 + 100; 
	case LOCAL_RECONCILIATION_TYPE:
	    return sizeof(signed_message) +
		sizeof(local_reconciliation_message); 
	case SITE_GLOBAL_VIEW_CHANGE_TYPE:
	    return sizeof(signed_message) + 
		sizeof(global_view_change_message); 
	case SITE_LOCAL_VIEW_PROOF_TYPE: 
	    return sizeof(signed_message) + 
		sizeof(local_view_proof_message); 
	case GLOBAL_RECONCILIATION_TYPE: 
	  return sizeof(signed_message) + 
	    sizeof(global_reconciliation_message);
	case COMPLETE_ORDERED_PROOF_TYPE: 

	case CCS_INVOCATION_TYPE:
	  return sizeof(signed_message) + sizeof(ccs_invocation_message);
	case CCS_REPORT_TYPE: 
	  return sizeof(signed_message) + sizeof(ccs_report_message);
	case CCS_DESCRIPTION_TYPE: 
	  return sizeof(signed_message) + sizeof(ccs_description_message);
	case CCS_UNION_TYPE:
	  return sizeof(signed_message) + sizeof(ccs_union_message);
	default:
	    return sizeof(signed_message) + rand() % 300;
    }

    return sizeof(signed_message) + rand() % 300;

}

/* Make a signed message with garbage */
signed_message* UTIL_ATTACK_Make_Garbage_Message() {

    signed_message *g;
    int32u i;
    byte *b;

    g = UTIL_New_Signed_Message();

    g->site_id = VAR.My_Site_ID;
    g->machine_id = VAR.My_Server_ID;
 
    g->type = rand() % 60;

    g->len = UTIL_ATTACK_Len( g->type );

    b = ((byte*)(g)) + sizeof(signed_message);

    for ( i = 0; i <= 800; i++ ) {
	b[i] = (byte)(rand()%1000);
    }

    UTIL_RSA_Sign_Message(g);

    return g;

}


void UTIL_ATTACK_Wage_War() {

    signed_message *mess;

    while ( 1 ) {
	mess = UTIL_ATTACK_Make_Garbage_Message();
	UTIL_Site_Broadcast(mess);
	usleep(50000);
	dec_ref_cnt(mess);
    }

} 
