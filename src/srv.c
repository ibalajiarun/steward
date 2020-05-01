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

#include <string.h>

#include "util/arch.h"
#include "util/alarm.h"
#include "util/sp_events.h"
#include "util/memory.h"
#include "util/data_link.h"

#include "net_types.h"
#include "objects.h"
#include "network.h"
#include "srv.h"
#include "data_structs.h"
#include "rep_election.h"
#include "utility.h"
#include "construct_collective_state_util.h"
#include "global_view_change.h"
#include "ordered_receiver.h"
#include "assign_sequence.h"
#include "local_reconciliation.h"
#include "error_wrapper.h"
#include "global_reconciliation.h"
#include "meta_globally_order.h"

#ifdef	ARCH_PC_WIN95
#include	<winsock.h>
WSADATA		WSAData;
#endif	/* ARCH_PC_WIN95 */

extern server_variables VAR;
extern network_variables NET;

/* Statics */
static void 	Usage(int argc, char *argv[]);
static void     Init_Memory_Objects(void);

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
#if 1
    Alarm_set(NONE);
#endif
#if 0 
    Alarm_set(CCS_PRINT | GRECON_PRINT | VALID_PRINT | CONFLICT_PRINT | 
	      NET_PRINT | RETRANS_PRINT );
#endif

#ifdef	ARCH_PC_WIN95    
    ret = WSAStartup( MAKEWORD(1,1), &WSAData );
    if( ret != 0 )
        Alarm( EXIT, "winsock initialization error %d\n", ret );
#endif	/* ARCH_PC_WIN95 */

    NET.program_type = NET_SERVER_PROGRAM_TYPE;  

    Alarm(PRINT,"Running Server %d in Site %d\n",
	    VAR.My_Server_ID, VAR.My_Site_ID );

    UTIL_Load_Addresses(); 
    //UTIL_Test_Server_Address_Functions(); 

    ERROR_WRAPPER_Initialize(); 

    E_init(); 
    Init_Memory_Objects();
    Init_Network();

    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys( VAR.My_Server_ID, VAR.My_Site_ID, RSA_SERVER ); 

    TC_Read_Partial_Key( VAR.My_Server_ID, VAR.My_Site_ID );
    TC_Read_Public_Key();
    
    UTIL_Initialize();    
    DAT_Initialize();
    
    ORDRCV_Initialize(); 
  
    REP_Initialize();     
    ASEQ_Initialize(); 
    LRECON_Initialize(); 
    GVC_Initialize();

    CCS_Initialize();
   
    GVC_Suggest_New_Global_View(); 
    REP_Suggest_New_Local_Representative(); 
    
    GLOBO_Initialize(); 
    GRECON_Init();

    fflush(0);

    /*Alarm(EXIT,"%d %d\n",sizeof(pending_slot_struct), 
    	    sizeof(global_slot_struct) );
    */

#if 0 
    if ( VAR.My_Server_ID == 4 ) {
        UTIL_ATTACK_Wage_War(); 
    }
#endif

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

static  void    Usage(int argc, char *argv[])
{
    char ip_str[16];
    int i1, i2, i3, i4; 
    int tmp;

    /* Setting defaults values */
    NET.My_Address = -1;
    NET.Port = 7100;
    /*Faults = 1;*/
    VAR.Faults = NUM_FAULTS;
    VAR.My_Server_ID = 1;
    VAR.My_Site_ID = 1;
    NET.Mcast_Address = 0;
	
    while(--argc > 0) {
        argv++;
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
	}else if((argc > 1)&&(!strncmp(*argv, "-f", 2))) {
	    sscanf(argv[1], "%d", &tmp);
	    VAR.Faults = tmp; 
	    if(3*VAR.Faults+1 >= MAX_NODES) {
		Alarm(EXIT, "Too many faults. There can only be %d servers in the site\n",
		      MAX_NODES-1);
	    }
	    argc--; argv++;
	}else 
#endif	  
	if((argc > 1)&&(!strncmp(*argv, "-l", 2))) {
            sscanf(argv[1], "%s", ip_str);
            sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            NET.My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
	    Alarm(PRINT,"My Address = "IPF"\n",IP(NET.My_Address));
            argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-i", 2))) {
	    sscanf(argv[1], "%d", &tmp);
	    VAR.My_Server_ID = tmp;
	    if(VAR.My_Server_ID > NUM_SERVERS_IN_SITE || VAR.My_Server_ID == 0
		    ) {
		Alarm(EXIT, "There are only %d servers in the site.\n"
			"Invalid id %d\n",
		      NUM_SERVERS_IN_SITE, VAR.My_Server_ID );
	    }
	    argc--; argv++;
	}else if((argc > 1)&&(!strncmp(*argv, "-s", 2))) {
	    sscanf(argv[1], "%d", &tmp);
	    VAR.My_Site_ID = tmp;
	    if(VAR.My_Site_ID > NUM_SITES || VAR.My_Site_ID == 0) {
		Alarm(EXIT, "There are only %d sites in the system\n"
		      "Invalid site id %d\n",
		      VAR.My_Site_ID,
		      NUM_SITES);
	    }
	    argc--; argv++;
	}else{

	    /* Commented out command line args that will be used in the release
	     * version. */
		Alarm(PRINT, "ERR: %d | %s\n", argc, *argv);	
		Alarm(PRINT, "Usage: \n%s\n%s\n%s\n%s\n%s\n%s\n",
		      /*"\t[-l <IP address>   ] : local address,",*/
		      /*"\t[-p <port number>  ] : local port, default is 7100,",*/
		      /*"\t[-m <mcast address>] : multicast address,",*/
		      /*"\t[-f <faults>       ] : number of faults, default is 1,",*/
		      "\t[-i <local ID>     ] : local ID, indexed base 1, default is 1"
		      "\t[-s <site  ID>     ] : site  ID, indexed base 1, default is 1"
		);
		Alarm(EXIT, "Bye...\n");
	}
    }

    if ( NET.Mcast_Address == 0 ) {
	NET.Mcast_Address = 225 << 24 | 2 << 16 | 1 << 8 | VAR.My_Site_ID;
	/* This sets the default mcast address to (225.2.1.site_id) */
	Alarm(DEBUG,"%d %d "IPF"\n", 
		VAR.My_Site_ID, VAR.My_Server_ID, IP(NET.Mcast_Address) );
    }
}

