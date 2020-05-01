#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include "TC.h"

void assert(int ret, int expect, char *s) {
  if (ret != expect) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1);
  } else {       
    fprintf(stdout, "%s ... OK\n", s);
  }
}                        

void assert_except(int ret, int except, char *s) {
  if (ret == except) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1); 
  } else {
    fprintf(stdout, "%s ... OK\n", s);
  }
} 

#define MAX_SITES 20

int main(int argc, char** argv)
{
	TC_DEALER *dealer[MAX_SITES+1];
	int nsite;

	int faults, n, k, keysize, num_sites;

	if (argc < 4)
	{
		fprintf(stderr, "Usage: %s keysize #faults directory\n", argv[0]);
		exit(1);
	}
	keysize = atoi(argv[1]);
	
	if (keysize != 256 && keysize != 512 && keysize != 1024 && keysize != 2048)
	{
		fprintf(stderr, "Invalid keysize. keysize should be 256/512/1024/2048.\n");
		exit(1);
	}
	faults = atoi(argv[2]);
	if (faults < 1)
	{
		fprintf(stderr, "Invalid #faults.\n");
		exit(1);
	}

	printf("Num Faults %d\n",faults);
	n = 3*faults+1;
	k = 1*faults+1;

	num_sites = atoi(argv[4]);
	if ( num_sites < 1 || num_sites > MAX_SITES ) {
		fprintf(stderr,"Invalid number of sites.\n");
	}

	for ( nsite = 1; nsite <= atoi(argv[4]); nsite++ ) {
		printf("%d\n",nsite);
 		dealer[nsite] = TC_generate(keysize/2, n, k, 17);
		//assert_except((int) dealer[nsite], (int) NULL, "TC_generate");

		TC_write_shares(dealer[nsite], argv[3], nsite);
		TC_DEALER_free(dealer[nsite]);
	}

	return 0;
}

