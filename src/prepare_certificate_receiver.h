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

#ifndef PREPARE_CERTIFICATE_RECEIVER_H1L1PO2Q3AH76FG5WEN
#define PREPARE_CERTIFICATE_RECEIVER_H1L1PO2Q3AH76FG5WEN 1

#define PCERT_TYPE_PREPARE_CERTIFICATE 1

#define PCERT_TYPE_PROPOSAL 1

/* Global Functions */
void PCRCV_Process_Message( signed_message *mess ); 

void PCRCV_Configure_Prepare_Certificate_Receiver( int32u local_view,
      int32u global_view, int32u seq_num, byte *update_digest ); 

void PCRCV_Clear_Pcert_Array(); 

#endif

