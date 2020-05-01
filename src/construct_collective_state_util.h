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

#ifndef CCS_UTILITY_H
#define CCS_UTILITY_H

#include "data_structs.h"
#include "construct_collective_state_protocol.h"

signed_message* Construct_CCS_Invocation( int32u context, int32u aru ); 
signed_message *Construct_CCS_Report(int32u aru, int32u context);

signed_message *Construct_CCS_Description(int32u context);
int32u Construct_CCS_Report_List(byte *Report_List, int32u aru, int32u context);
int32u Construct_CCS_Description_List(char *des_list, int32u context);
int32u Construct_Union_Message_And_ARU(unsigned char *buf, int32u *site_aru, 
				       int32u context);

signed_message *CCS_Construct_Threshold_Share(int32u context);

void Send_Described_Reports(signed_message *m);
void Send_Report_Contents(int32u rep_id, signed_message *m);
void Send_Union_Contents(int32u context);

int32u Get_Max_ARU(int32u context);  

int32u Is_Global_Slot_Ordered (global_slot_struct  *gss);
int32u Is_Pending_Slot_Ordered(pending_slot_struct *pss);

int32u Is_Global_Slot_Intermediate (global_slot_struct  *gss);
int32u Is_Pending_Slot_Intermediate(pending_slot_struct *pss);

int32u My_ARU_Is_Sufficient(int32u context);  

void CCS_Reset_Data_Structures(int32u context);

ccs_union_entry *Get_New_Union_Entry(void);

ccs_global_report_entry *Get_Report_Entry(ccs_report_message *report, int32u i);
description_entry *Get_Description_Entry(ccs_description_message *description,
					 int32u i);
void CCS_Initialize();

#endif
