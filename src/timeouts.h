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

/* Timeouts */
#ifndef TIMEOUTS_JSAHKJ43Q5H1AF28SAMK9JASI
#define TIMEOUTS_JSAHKJ43Q5H1AF28SAMK9JASI 1

#include "util/sp_events.h"

static const sp_time timeout_l_new_rep_retrans = { 0, 200000 }; 
/* SPEED */
static const sp_time timeout_pre_prepare_retrans = { 0, 500000 }; 

/* FINAL was 1 sec */
static const sp_time timeout_proposal_retrans = { 0, 500000 }; 

static const sp_time timeout_accept_share_minimum_retrans = { 1, 0 }; 

static const sp_time timeout_local_reconciliation = { 0, 40000 };

static const sp_time timeout_global_reconciliation = { 0, 500000 };

static const sp_time timeout_local_reconciliation_aru_global_proof = { 1, 0 };

static const sp_time timeout_local_reconciliation_request = { 0, 10000 };

static const sp_time timeout_local_reconciliation_auto_reconciliation = { 0, 100000 }; 

static const sp_time timeout_attempt_to_send_proposal = { 0, 6000 };

static const sp_time timeout_global_view_change_send_proof = { 1, 100000 };

static const sp_time timeout_zero = { 0, 0 }; 

static const sp_time timeout_client = { 1, 0 }; 

#endif
