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

/* data_structs.c: This file contains all globally defined data structures.
 * This corresponds closely to the datastructure section of the pseudocode. The
 * structures are defined in data_structs.h and the variables are defined here.
 * We also define initialization and utility functions. */

/* Globally Accessible Variables -- These should be the only global variables
 * in the program -- Note that global does not refer to "global ordering" but
 * instead to standard global variables in C */

#include "data_structs.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "stopwatch.h"

/* The globally accessible variables */

server_variables VAR;

network_variables NET;

global_data_struct GLOBAL;

pending_data_struct PENDING;

client_data_struct CLIENT;

int32 sd;

/* Data structure initialization funtions */

void Initialize_Prepare_Certificate(  ) {
    
}

void DAT_Initialize() {

    int32u cli_index;
    int32u site_index;

    /* Initialize local variables */
    
    GLOBAL.ARU = 0;
    GLOBAL.View = 0;        /* These values could be read from a file that contains the greatest installed views. */ 
    GLOBAL.Installed = 1; 
    GLOBAL.Max_ordered = 0;
 
    PENDING.ARU = 0;
    PENDING.Is_preinstalled = 1; 
    PENDING.View = 0;

    GLOBAL.maximum_pending_view_when_progress_occured = 1;

    for ( site_index = 0; site_index <= NUM_SITES; site_index++ ) {
    	for ( cli_index = 0; cli_index <= NUM_CLIENTS; cli_index++ ) {
	    CLIENT.client[site_index][cli_index].pending_time_stamp = 0;
	    CLIENT.client[site_index][cli_index].globally_ordered_time_stamp =
		0;
	    CLIENT.client[site_index][cli_index].global_seq_num = 0;
	}
	PENDING.Local_view_proof[ site_index ] = NULL;
    }

}


