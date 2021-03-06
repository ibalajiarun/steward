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

/* Protocol 1 Functions. These functions can be used to either dispatch a
 * protocol 1 mesage to the appropriate handler function OR to a server can
 * invoke ASSIGN-SEQ on an update. */

#ifndef PROT_ASEQ_NORMAL_CASE_A1K3SJ5A7S
#define PROT_ASEQ_NORMAL_CASE_A1K3SJ5A7S

#include "data_structs.h"

/* Dispatch message that belongs to ASSIGN-SEQ */
void ASEQ_Dispatcher( signed_message *mess ); 

/* Handle a proposal that has been generated by combining signature shares. */
void ASEQ_Handle_Proposal( signed_message *proposal );

int32u ASEQ_Update_ARU();

void ASEQ_Initialize();

void ASEQ_Process_Proposal( signed_message *proposal ); 

void ASEQ_Process_Next_Proposal(); 

void ASEQ_Process_Next_Update(); 

void ASEQ_Reset_For_Pending_View_Change();

#endif
