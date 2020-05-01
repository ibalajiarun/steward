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

/* This file contains error functions that can be called when a problem occurs
 * that should not happen or when validation fails. For debugging we sometimes
 * want to exit if there is a validation failure or a conflict. However, when
 * the protocol is tested, we want to make sure that we do not exit when an
 * unexpected event occurs (or sometimes expected when under attack). All exits
 * should occur through these functions. */

#include "util/alarm.h"
#include "data_structs.h"

extern server_variables VAR;

extern network_variables NET;

FILE *log_file;

void VALIDATE_FAILURE_Init(); 


void ERROR_WRAPPER_Initialize() {

    VALIDATE_FAILURE_Init(); 

}

void VALIDATE_FAILURE_Init() {

    /* Open a validate failure log for server */

#if OUTPUT_VALIDATION_FAILURES

    char name[100];

    sprintf(name,"validate_fail.%02d_%02d.log",
	    VAR.My_Site_ID,VAR.My_Server_ID);

    if ( NET.program_type == NET_SERVER_PROGRAM_TYPE ) {  

	/* Only log server validation failures. */
	log_file = fopen( name, "w" );

	if ( log_file == NULL ) {
	    Alarm(PRINT,"Failed to open validate log file.\n");
	}

    }

#endif

}

void VALIDATE_FAILURE( const char* message ) {
    Alarm(DEBUG,"Validate Failure: %s\n",message);
}

void VALIDATE_FAILURE_LOG( signed_message *mess, int32u num_bytes ) {

#if OUTPUT_VALIDATION_FAILURES
    if ( NET.program_type == NET_SERVER_PROGRAM_TYPE ) {  
	
	Alarm(DEBUG,"Validate Failure (Logged): %s\n",mess);

	if ( log_file == NULL ) {
	    return;
	}

	if ( num_bytes < sizeof(signed_message) ) {
	    /* Fragement message */
	    fprintf(log_file,"fragment message, recv len: %d\n", num_bytes);
	} else {
	    /* Log some stats about message */
	    fprintf(log_file,
	        "source: s:%d id:%d type: %d claimed len: %d recv len: %d\n",
		    mess->site_id, mess->machine_id, mess->type,
		    mess->len + (int32u)sizeof(signed_message), num_bytes);
	}
    }
    fflush(0);
#endif    
}

void CONFLICT_FAILURE( const char* message ) {
    Alarm(PRINT,"Conflict: %s\n",message);
}

void INVALID_MESSAGE( const char* message ) {
    Alarm(PRINT,"Invalid Message: %s\n",message);
}


