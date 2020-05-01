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

/* Openssl RSA signing and verifying functionality. The openssl_rsa.h header
 * file lists the public functions that can be used to sign messages and verify
 * that signatures are valid. */

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include "openssl_rsa.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>

#include "data_structs.h"
#include "util/arch.h"
#include "util/alarm.h"
#include "util/sp_events.h"
#include "util/data_link.h"
#include "util/memory.h"

/* Defined Types */

#define RSA_TYPE_PUBLIC    1
#define RSA_TYPE_PRIVATE   2
#define RSA_TYPE_CLIENT_PUBLIC   3 
#define RSA_TYPE_CLIENT_PRIVATE  4 
#define DIGEST_ALGORITHM   "sha1"
#define NUMBER_OF_SERVERS  NUM_SERVERS_IN_SITE 
#define NUMBER_OF_CLIENTS  NUM_CLIENTS

/* This flag is used to remove crypto for testing -- this feature eliminates
 * security and Byzantine fault tolerance. */
#define REMOVE_CRYPTO 0  

/* Globals */
RSA *private_rsa; /* My Private Key */
RSA *public_rsa_by_server[NUM_SITES+1][NUMBER_OF_SERVERS + 1];
RSA *public_rsa_by_client[NUM_SITES+1][NUMBER_OF_CLIENTS + 1];
const EVP_MD *message_digest;
void *pt;

void Gen_Key_Callback( int32 stage, int32 n, void *unused ) {

}

void Write_BN( FILE *f, BIGNUM *bn ) {

    char *bn_buf;
    
    bn_buf = BN_bn2hex( bn );

    fprintf( f, "%s\n", bn_buf );

    /* Note: The memory for the BIGNUM should be freed if the bignum will not
     * be used again. */
    
}

void Write_RSA( int32u rsa_type, int32u server_number, int32u site_number, RSA *rsa ) {

    /* Write an RSA structure to a file */

    FILE *f;
    char fileName[50];
    char dir[100] = "./keys";

    if ( rsa_type == RSA_TYPE_PUBLIC ) {
	sprintf(fileName,"%s/public_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_PRIVATE ) {
	sprintf(fileName,"%s/private_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_CLIENT_PUBLIC ) {
	sprintf(fileName,"%s/public_client_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
	sprintf(fileName,"%s/private_client_%02d_%02d.key",dir,site_number,server_number);
    }
     
    f = fopen( fileName, "w" );

   
    Write_BN( f, rsa->n );
    Write_BN( f, rsa->e );
    if ( rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
	Write_BN( f, rsa->d );
	Write_BN( f, rsa->p );
	Write_BN( f, rsa->q );
	Write_BN( f, rsa->dmp1 );
	Write_BN( f, rsa->dmq1 );
	Write_BN( f, rsa->iqmp );
    }
    fprintf( f, "\n" );
    fclose(f);
}

void Read_BN( FILE *f, BIGNUM **bn ) {

    (*bn) = BN_new();
    
    char bn_buf[1000];

    fgets(bn_buf, 1000, f);
    BN_hex2bn( bn, bn_buf );

}

void Read_RSA( int32u rsa_type, int32u server_number, int32u site_number, RSA *rsa ) {

    /* Read an RSA structure to a file */

    FILE *f;
    char fileName[50];
    char dir[100] = "./keys";
    
    if ( rsa_type == RSA_TYPE_PUBLIC ) {
	sprintf(fileName,"%s/public_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_PRIVATE ) {
	sprintf(fileName,"%s/private_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_CLIENT_PUBLIC ) {
	sprintf(fileName,"%s/public_client_%02d_%02d.key",dir,site_number,server_number);
    } else if ( rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
	sprintf(fileName,"%s/private_client_%02d_%02d.key",dir,site_number,server_number);
    } 

#if 0 
    printf("Opening file: %s\n",fileName);
#endif    

    f = fopen( fileName, "r" );

    if ( f == NULL ) {
	Alarm(EXIT,"   ERROR: Could not open the key file: %s\n", fileName );
    }
 
    Read_BN( f, &rsa->n );
    Read_BN( f, &rsa->e );
    if ( rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
	Read_BN( f, &rsa->d );
	Read_BN( f, &rsa->p );
	Read_BN( f, &rsa->q );
	Read_BN( f, &rsa->dmp1 );
	Read_BN( f, &rsa->dmq1 );
	Read_BN( f, &rsa->iqmp );
    }
}


/* This function generates keys based on the current configuration as specified
 * in data_structs.h */
void OPENSSL_RSA_Generate_Keys() {

    RSA *rsa;
    int32u s;
    int32u nsite;

    /* Prompt user for a secret key value. */

    for ( nsite = 1; nsite <= NUM_SITES; nsite++ ) {
	/* Generate Keys For Servers */
 	for ( s = 1; s <= NUMBER_OF_SERVERS; s++ ) {
	    rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
	    RSA_print_fp( stdout, rsa, 4 );
	    Write_RSA( RSA_TYPE_PUBLIC, s, nsite, rsa ); 
	    Write_RSA( RSA_TYPE_PRIVATE, s, nsite, rsa ); 
	} 
	/* Generate Keys For Clients */
 	for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
	    rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
	    RSA_print_fp( stdout, rsa, 4 );
	    Write_RSA( RSA_TYPE_CLIENT_PUBLIC, s, nsite, rsa ); 
	    Write_RSA( RSA_TYPE_CLIENT_PRIVATE, s, nsite, rsa ); 
	} 
    }
}

/* Read all of the keys for servers or clients. All of the public keys
 * should be read and the private key for this server should be read. */
 void OPENSSL_RSA_Read_Keys(  int32u my_number, int32u my_site,  int32u type )
{

    int32u s; 
    int32u rt;
    int32u nsite;
    
    for ( nsite = 1; nsite <= NUM_SITES; nsite++ ) {    
	/* Read all public keys for servers. */
	for ( s = 1; s <= NUMBER_OF_SERVERS; s++ ) {
	    public_rsa_by_server[nsite][s] = RSA_new();
	    Read_RSA( RSA_TYPE_PUBLIC, s, nsite, public_rsa_by_server[nsite][s] );
#if 0
	    RSA_print_fp( stdout, public_rsa_by_server[nsite][s], 4 );
#endif
	} 
	/* Read all public keys for clients. */
	for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
	    public_rsa_by_client[nsite][s] = RSA_new();
	    Read_RSA( RSA_TYPE_CLIENT_PUBLIC, s,
		    nsite, public_rsa_by_client[nsite][s] );
#if 0
	    RSA_print_fp( stdout, public_rsa_by_server[nsite][s], 4 );
#endif
	} 
    }
    
    if ( type == RSA_SERVER ) {
	rt = RSA_TYPE_PRIVATE;
    } else if ( type == RSA_CLIENT ) {
	rt = RSA_TYPE_CLIENT_PRIVATE;
    } else {
        printf("OPENSSL_RSA_Read_Keys: Called with invalid type.\n");
	exit(0);
    }

    /* Read my private key. */
    private_rsa = RSA_new();
    Read_RSA( rt, my_number, my_site, private_rsa );
#if 0
    RSA_print_fp( stdout, private_rsa, 4 );
#endif

}

void OPENSSL_RSA_Init() {

    /* Load a table containing names and digest algorithms. */
    OpenSSL_add_all_digests();

    /* Use sha1 as the digest algorithm. */
    message_digest = EVP_get_digestbyname( DIGEST_ALGORITHM );

}

int32u OPENSSL_RSA_Digests_Equal( unsigned char *digest1, unsigned char *digest2 ) {

    int32u i;

#if REMOVE_CRYPTO    
    return 1;
#endif    
    
    for ( i = 0; i < DIGEST_SIZE; i++ ) {
	if ( digest1[i] != digest2[i] ) return 0;
    }
    return 1;
}

void OPENSSL_RSA_Make_Digest( const void *buffer, size_t buffer_size, 
	unsigned char *digest_value ) {

    /* EVP functions are a higher level abstraction that encapsulate many
     * different digest algorithms. We currently use sha1. The returned digest
     * is for sha1 and therefore we currently assume that functions use
     * this type of digest. It would be best to extend the encapsulation
     * through our code. Note that there may be an increase in
     * computational cost because these high-level functions are used. */
    
    EVP_MD_CTX mdctx;
    int32u md_len;
    
#if REMOVE_CRYPTO 
    return;
#endif
    
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, message_digest, NULL);
    EVP_DigestUpdate(&mdctx, buffer, buffer_size);
    EVP_DigestFinal_ex(&mdctx, digest_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);

    /* Check to determine if the digest length is expected for sha1. It should
     * be 20 bytes. */
   
    if ( md_len != 20 ) {
	printf("An error occurred while generating a message digest.\n"
		"The length of the digest was set to %d. It should be 20.\n"
		, md_len);
	exit(0);
    }

}

void OPENSSL_RSA_Print_Digest( unsigned char *digest_value ) {

    int32u i;
    
    for(i = 0; i < DIGEST_SIZE; i++) printf("%02x", digest_value[i]);
    printf("\n");

}

void OPENSSL_RSA_Make_Signature( const byte *digest_value, 
	byte *signature ) {

    /* Make a signature for the specified digest value. The digest value is
     * assumed to be 20 bytes. */
    
    int32u signature_size;
    sp_time start, end, diff;

#if REMOVE_CRYPTO
    return;
#endif

    if ( private_rsa == NULL ) {
	printf("Error: In Make_Signature, private_rsa key is NULL.\n");
	exit(0);
    }

    start = E_get_time();

    RSA_sign(NID_sha1, digest_value, 20, signature, &signature_size,
	    private_rsa );

    end = E_get_time();

    diff = E_sub_time(end, start);
    Alarm(DEBUG, "Signing: %d sec; %d microsec\n", diff.sec, diff.usec);

}

int32u OPENSSL_RSA_Verify_Signature( const byte *digest_value, unsigned
	char *signature,  int32u number,  int32u site, int32u type ) {

    /* Verify a signature for the specified digest value. The digest value is
     * assumed to be 20 bytes. */
   
    int32 ret;
    RSA *rsa; 

#if REMOVE_CRYPTO 
    return 1;
#endif
    
    if ( type == RSA_CLIENT ) {
	if (number < 1 || number > NUMBER_OF_CLIENTS ) {
	    return 0;
	}
	rsa = public_rsa_by_client[site][number];
    } else {
	if (number < 1 || number > NUMBER_OF_SERVERS ) {
	    return 0;
	}
        rsa = public_rsa_by_server[site][number];
    }
    
    ret = RSA_verify(NID_sha1, digest_value, 20, signature, SIGNATURE_SIZE,
	    rsa );

    if ( !ret ) {
	printf("RSA_OPENSSL_Verify: Verification Failed. "
		"Machine number = %d.\n",
		number);
    }

    return ret; 
}

void OPENSSL_RSA_Sign( const byte *message, size_t message_length,
       byte *signature ) {

    byte md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    return;
#endif

    OPENSSL_RSA_Make_Digest( message, message_length, md_value );

    OPENSSL_RSA_Make_Signature( md_value, signature );

#if 0    
    Alarm( PRINT," verify 1 %d\n",
	   OPENSSL_RSA_Verify_Signature( md_value, signature, 1, 
	   RSA_SERVER ));

    Alarm( PRINT," verify 2 %d\n",
	   OPENSSL_RSA_Verify( message, message_length, signature, 1, 
	   RSA_SERVER ));
#endif

}

int OPENSSL_RSA_Verify( const byte *message, size_t message_length,
       byte *signature, int32u number, int32u site, int32u type ) {
 
    byte md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    return 1;
#endif    

    OPENSSL_RSA_Make_Digest( message, message_length, md_value );
    return OPENSSL_RSA_Verify_Signature( md_value, signature, number, site, type );

}

