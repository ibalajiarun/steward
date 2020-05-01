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

#ifndef ERROR_WRAPPER_KJ1AKJS9F23NM50QLSD
#define ERROR_WRAPPER_KJ1AKJS9F23NM50QLSD 1

#include "data_structs.h"

void VALIDATE_FAILURE( const char* message ); 

void CONFLICT_FAILURE( const char* message );

void INVALID_MESSAGE( const char* message );

void VALIDATE_FAILURE_LOG( signed_message *mess, int32u num_bytes ); 

void ERROR_WRAPPER_Initialize(); 

#endif
