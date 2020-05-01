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

/* Openssl initiation, sign, and verify functions. These functions can be used
 * to easily use openssl to create RSA signatures and to verify these RSA
 * signatures. The functions listed below use RSA and sha1 digests. */

#ifndef OPENSSL_RSA_ADK34JS63F7DJKA
#define OPENSSL_RSA_ADK34JS63F7DJKA x

#include <stdio.h>
#include "util/arch.h"

/* Public definitions */

#define DIGEST_SIZE        20
#define SIGNATURE_SIZE     128
#define RSA_CLIENT         1
#define RSA_SERVER         2

/* Public functions */

void OPENSSL_RSA_Sign( const unsigned char *message, size_t message_length,
       unsigned char *signature ); 

int OPENSSL_RSA_Verify( const unsigned char *message, size_t message_length,
	unsigned char *signature, int32u server_number, int32u site, int32u type ); 
 
void OPENSSL_RSA_Init();

void OPENSSL_RSA_Read_Keys( int32u my_number, int32u my_site, int32u type ); 

void OPENSSL_RSA_Generate_Keys(); 

void OPENSSL_RSA_Make_Signature( const unsigned char *digest_value, unsigned
	char *signature ); 

int32u OPENSSL_RSA_Verify_Signature( const unsigned char *digest_value, unsigned
	char *signature, int32u number, int32u site, int32u type ); 

int32u OPENSSL_RSA_Digests_Equal( unsigned char *digest1, unsigned char *digest2 ); 

void OPENSSL_RSA_Make_Digest( const void *buffer, size_t buffer_size, unsigned 
	char *digest_value ); 

void OPENSSL_RSA_Print_Digest( unsigned char *digest_value ); 

#endif

