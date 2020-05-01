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

#ifndef REP_ELECTION_AK3LJAS3K5L6J8FL7AS5FYU2WBRM
#define REP_ELECTION_AK3LJAS3K5L6J8FL7AS5FYU2WBRM

/* Local Representative Election */

void REP_Suggest_New_Local_Representative(); 

int32u REP_Get_Suggested_View( signed_message *mess ); 

void REP_Initialize(); 

void REP_Update_Preinstall_Status(); 

int32u REP_Get_View_From_Proof(signed_message *local_proof);

void REP_Handle_Local_View_Proof_Message( signed_message *local_view_proof ); 

int32u REP_Preinstall_Proof_View_From_Proof_Message(); 

int32u REP_Preinstall_Proof_View_From_L_New_Rep(); 

void REP_Process_Message( signed_message *mess );

#endif
