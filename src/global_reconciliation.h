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

#ifndef GLOBAL_RECONSILIATION_JADBKENWWAMNAS55F34JB  
#define GLOBAL_RECONSILIATION_JADBKENWWAMNAS55F34JB

void GRECON_Start_Reconciliation( int32u target ); 

void GRECON_Dispatcher( signed_message *mess ); 

void GRECON_Send_Request();

#if 0
int32u GRECON_Process_Complete_Ordered_Proof(signed_message *mess, 
					     int32u num_bytes);
#endif

int32u GRECON_Process_Complete_Ordered_Proof(signed_message *mess, 
					     int32u num_bytes, 
					     signed_message **ret_prop, 
					     int32u caller_is_client);

signed_message* GRECON_Construct_Ordered_Proof_Message( int32u seq_num ); 

void GRECON_Init();

void GRECON_Send_Response( int32u seq_num, int32u site, int32u server ); 

#endif


