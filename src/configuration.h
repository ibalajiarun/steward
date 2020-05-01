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
/* Administrator configurable parameters */

#define NUM_FAULTS   1    /* Number of faults tolerated in each site */        
#define NUM_SITES    5    /* Number of local area sites */ 
#define NUM_CLIENTS  5	  /* Maximum number of clients in each site */

/* This EMULATE_NON_REP_SITE can be set so that all sites except the leader
 * site are emulated.  This means that a single server runs a busy wait for
 * the time required to compute a threshold signature and generate a wide-area
 * accept message. The flag is used for testing large systems. */

#define EMULATE_NON_REP_SITE 0     /* Emulate the non leader sites -- for
				      testing */

#define SERVER_OUTPUT_THROUGHPUT 1  /* Output data regarding system speed */

#define CLIENT_OUTPUT_LATENCY 1  /* Output data regarding system speed */ 

#define OUTPUT_VALIDATION_FAILURES 1  /* Write to a log when server receives a
					 message that does not validate
					 correctly */ 

#define OUTPUT_STATE_MACHINE 1     /* Output the ordered stream of updates */


