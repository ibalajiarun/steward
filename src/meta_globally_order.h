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

#ifndef ACCEPT_HG2A4D5M6B7234NF6W7W89L1FF
#define ACCEPT_HG2A4D5M6B7234NF6W7W89L1FF 1

/* Generates an Accept message based on a proposal that is received from a
 * different site */

#include "data_structs.h"

void GLOBO_Process_Proposal( signed_message *proposal );
void GLOBO_Dispatcher( signed_message *mess );
void GLOBO_Handle_Accept( signed_message *accept ); 
void GLOBO_Handle_Global_Ordering( global_slot_struct *slot);
void GLOBO_Initialize(); 
void GLOBO_Reset_Global_Progress_Bookkeeping_For_Global_View_Change(); 
void GLOBO_Reset_Global_Progress_Bookkeeping_For_Local_View_Change();  
int32u GLOBO_Is_Progress_Being_Made_For_Global_View_Change(); 
int32u GLOBO_Is_Progress_Being_Made_For_Local_View_Change(); 


#endif
