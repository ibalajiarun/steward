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

/* The conflict code (conflict.h and conflict.c) verifies whether the 
 * content of an incoming message is in conflict with existing data
 * structures.
 */ 


#ifndef CONFLICT_P9SK0D3ENBG5JCH2QI
#define CONFLICT_P9SK0D3ENBG5JCH2QI 1

#include "util/arch.h"
#include "data_structs.h"



/* Conflict Functions */

/* Public */
int32u CONFL_Check_Message( signed_message *message, int32u num_bytes ); 

#endif 
