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


/* Utility functions to access data structures, create packets, and do other
 * commonly performed tasks. */

#ifndef UTILITY_ASDJ4NA2K2FNWQ1MNC5H6Y7G8FE
#define UTILITY_ASDJ4NA2K2FNWQ1MNC5H6Y7G8FE

#include "stopwatch.h"
#include "util/sp_events.h"

 
global_slot_struct* UTIL_Get_Global_Slot( int32u seq_num );

global_slot_struct* UTIL_Get_Global_Slot_If_Exists( int32u seq_num );
    
pending_slot_struct* UTIL_Get_Pending_Slot( int32u seq_num );

pending_slot_struct* UTIL_Get_Pending_Slot_If_Exists( int32u seq_num );

void UTIL_Initialize();

signed_message* UTIL_New_Signed_Message();

int32u UTIL_Leader_Site(); 

int32u UTIL_Representative(); 

int32u UTIL_Get_Site_Representative( int32u site_id ); 

int32u UTIL_I_Am_In_Leader_Site(); 

int32u UTIL_I_Am_Representative(); 

void UTIL_RSA_Sign_Message( signed_message *mess ); 

void UTIL_Site_Broadcast( signed_message *mess ); 

int32 UTIL_Get_Server_Address( int32u site, int32u server ); 

int32 UTIL_Get_Server_Spines_Address( int32u site, int32u server ); 

void UTIL_Test_Server_Address_Functions(); 

void UTIL_Load_Addresses();

int32u UTIL_Get_ARU(int32u context);

int32u UTIL_Get_View(int32u context);

void UTIL_Send_To_Server( signed_message *mess, int32u site_id, int32u server_id ); 

void UTIL_Send_To_Site_Representatives( signed_message *mess );

void UTIL_Send_To_Site_Servers_With_My_ID(signed_message *mess);


void UTIL_Send_To_Client( int32 address, int32u site, int32u id, signed_message
	*mess ); 

void UTIL_Stopwatch_Start( util_stopwatch *stopwatch ); 

void UTIL_Stopwatch_Stop( util_stopwatch *stopwatch ); 

double UTIL_Stopwatch_Elapsed( util_stopwatch *stopwatch );

typedef struct dummy_dll_node_struct {
    void *data;
    int32u int32u_1;  /* generic integer */
    void *next;
} dll_node_struct;

typedef struct dummy_dll_struct {
    dll_node_struct *begin;
    dll_node_struct *current_position;
    dll_node_struct *end;
} dll_struct;

void UTIL_DLL_Clear( dll_struct *dll ); 

void UTIL_DLL_Next( dll_struct *dll );

int32u UTIL_DLL_At_End( dll_struct *dll ); 

void UTIL_DLL_Set_Begin( dll_struct *dll );

signed_message* UTIL_DLL_Get_Signed_Message( dll_struct *dll ); 

void UTIL_DLL_Add_Data( dll_struct *dll, void *data ); 

int32u UTIL_DLL_Is_Empty( dll_struct *dll ); 

signed_message* UTIL_DLL_Front_Message( dll_struct *dll ); 

void UTIL_DLL_Pop_Front( dll_struct *dll ); 

void UTIL_DLL_Set_Last_Int32u_1( dll_struct *dll, int32u val ); 

int32u UTIL_DLL_Front_Int32u_1( dll_struct *dll ); 

#define UTIL_RETRANS_DEFAULT               0
#define UTIL_RETRANS_TO_SERVERS_WITH_MY_ID 1
#define UTIL_RETRANS_TO_LEADER_SITE_REP    2

typedef struct dummy_retrans_struct {
    /* The following should not be set by the user */
    dll_struct dll;
    //stdit it;
    int32u is_started;
    /* Public, user specified flags and variables */
    int32u repeat;
    sp_time inter_message_time;
    sp_time inter_group_time;
    int32u dest_site_id;
    int32u dest_server_id;
    int32u type;
} retrans_struct; 

void UTIL_RETRANS_Construct( retrans_struct *retrans ); 

void UTIL_RETRANS_Add_Message( retrans_struct *retrans, signed_message *message ); 

void UTIL_RETRANS_Clear( retrans_struct *retrans );

void UTIL_RETRANS_Start( retrans_struct *retrans ); 

void UTIL_RETRANS_Send_Next( int dummy, void *retrans_data ); 

int32u UTIL_Is_Globally_Ordered( int32u seq_num ); 

int32u UTIL_Is_Pending_Proposal_Ordered( int32u seq_num );

int UTIL_int_cmp( const void *i1, const void *i2 ); 

int32u UTIL_hashcode( const void *n ); 

void UTIL_Busy_Wait( double sec ); 

int32u UTIL_Number_Of_Clients_Seen(); 

void UTIL_Add_To_Mess_Count( int32u type ); 

void UTIL_Dump_Mess_Count(); 

void UTIL_Apply_Update_To_State_Machine( signed_message *proposal ); 

/* CCS Utilities called by functions external to CCS */

void UTIL_Update_CCS_STATE_PENDING( int32u seq_num ); 

void UTIL_Update_CCS_STATE_GLOBAL( int32u seq_num ); 

/* CLIENT */

int32u UTIL_CLIENT_Process_Update( signed_message *update ); 

void UTIL_CLIENT_Process_Globally_Ordered_Proposal( signed_message *proposal ); 

void UTIL_CLIENT_Respond_To_Client(signed_message *update, int32u seq_num);

void UTIL_CLIENT_Reset_On_View_Change(); 

/* PURGATORY */

void UTIL_PURGE( signed_message **m ); 

void UTIL_Purge_Pending_Slot( signed_message *pre_prepare ); 

void UTIL_Purge_Pending_Slot_Seq( int32u seq_num ); 

void UTIL_Purge_Global_Slot( signed_message *proposal ); 

#endif
