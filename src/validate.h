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

/* The validation code (validate.h and validate.c) makes sure that messages are
 * authentic by verifying signatures and makes sure that the messages have the
 * expected lengths based on what type they are. It also insures that any
 * specified sender (client, server, or site) is valid. */

#ifndef VALIDATE_A4AWM5AE2FUR5MQ6KS
#define VALIDATE_A4AWM5AE2FUR5MQ6KS 1

#include "util/arch.h"
#include "data_structs.h"

#define VAL_TYPE_INVALID       1
#define VAL_SIG_TYPE_SERVER    2
#define VAL_SIG_TYPE_SITE      3
#define VAL_SIG_TYPE_CLIENT    4

/* Validation Functions */

/* Public */
int32u VAL_Validate_Message( signed_message *message, int32u num_bytes ); 

#endif 
