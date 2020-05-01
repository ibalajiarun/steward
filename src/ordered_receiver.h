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

#ifndef ORDERED_RECEIVER_AM0DMF97KWW5LFBQK12113D4IF6U 
#define ORDERED_RECEIVER_AM0DMF97KWW5LFBQK12113D4IF6U 1

signed_message* ORDRCV_Construct_Ordered_Proof_Message( signed_message *proposal );

void ORDRCV_Initialize(); 

void ORDRCV_Process_Ordered_Proof_Message( signed_message *op_mess ); 

void ORDRCV_Process_Accept( signed_message *accept ); 

void ORDRCV_Send_Ordered_Proof_Bundle( int32u seq_num, 
       int32u site_id, int32u server_id	); 

#endif
