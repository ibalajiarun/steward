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

#ifndef PROT_THRESH_K2JAS3KJ4B5B6WMD7UI8VC
#define PROT_THRESH_K2JAS3KJ4B5B6WMD7UI8VC

#include "data_structs.h"

void THRESH_Process_Threshold_Share( signed_message *mess ); 
int32u THRESH_Attempt_To_Combine( signed_message **sig_share, 
      signed_message *dest_mess ); 
void THRESH_Invoke_Threshold_Signature( signed_message *mess ); 


#endif
