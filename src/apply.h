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

#ifndef APPLY_KJAF7NA8M9W2BBQK23LOJAG1HD
#define APPLY_KJAF7NA8M9W2BBQK23LOJAG1HD 1

void APPLY_Message_To_Data_Structs( signed_message *mess ); 

/* Global predicates */

/* Is the prepare certificate ready? The prepare certifiacate consists of a
 * pointer to a pre_prepare message and an array of prepare messages where the
 * array has an entry for each server. */
int32u APPLY_Prepare_Certificate_Ready( signed_message *pre_prepare,
       signed_message **prepare, int32u alert_mismatch );

/* Move a prepare certificate */
void APPLY_Move_Prepare_Certificate( signed_message **pre_prepare_src,
	signed_message **prepare_src, pending_slot_struct *slot );

void APPLY_Proposal( signed_message *proposal );

int32u APPLY_Prepare_Matches_Pre_Prepare( signed_message *prepare, 
	signed_message *pre_prepare );

signed_message *APPLY_Get_Content_Message_From_Sig_Share(
						   signed_message *sig_share);

#endif
