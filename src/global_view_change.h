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

#ifndef PROT_GVC_A1KJ2S8HKU3J6WEAOI42Q 
#define PROT_GVC_A1KJ2S8HKU3J6WEAOI42Q 1  

#include "data_structs.h"

void GVC_Suggest_New_Global_View(); 

/* Handle a view change. */
void GVC_Handle_Global_View_Change_Message( signed_message *gvc ); 

/* Get the view */
int32u GVC_Get_View( signed_message *global_view_change ); 

void GVC_Process_Message( signed_message *mess ); 

void GVC_Initialize();

#endif

