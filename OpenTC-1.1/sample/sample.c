#include <TC.h>

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


void test(int keysize, int faults, int proof, int partial_combine) {
  TC_DEALER *tcd;
  TC_IND **tcinds;
  TC_IND_SIG **tcsigs;
  TC_IND_SIG *sig;
  TC_SIG csig;
  TC_PK *tcpk;
  int n, k;
  int i, ret;
  BIGNUM *hM;
  
  // RAND_seed();
  
  // Initialization
  n = 3*faults+1;
  k = faults+1;

  printf("keysize = %d, #faults = %d, n = %d, k = %d\n",
         keysize, faults, n, k);

  hM = BN_new();
  BN_set_word(hM, random());

  tcinds = (TC_IND**) malloc(n*sizeof(TC_IND*));
  tcsigs = TC_SIG_Array_new(n);
  sig = TC_IND_SIG_new();

  // Generate public key and individual shares
  tcd = TC_generate(keysize/2, n, k, 3);
  assert_except((int) tcd, (int) NULL, "TC_generate");
  
  for (i=0; i<n; i++) {
    tcinds[i] = TC_get_ind(i+1, tcd);
  }

  // Generate individual signatures
  for (i=0; i<n; i++) {
    ret = genIndSig(tcinds[i], hM, sig, proof);
    assert(ret, TC_NOERROR, "genIndSig");
      
    set_TC_SIG(i+1, sig, tcsigs);
  }

  // Combine individual sigatures
  if (partial_combine) {
    BIGNUM *wexps;
    int **sets = NULL;
    
    // array of Set_S: distributed on individual node in a truly parallel setting 
    sets = (int**) malloc(k*sizeof(int*));

    // array of partial exponents of w: each individual node maintains its copy independently
    wexps = (BIGNUM*) malloc(k*sizeof(BIGNUM));
   
    // Phase 1: generate individual partial exponent of w
    for (i=0; i<k; i++) {
      BN_init(&(wexps[i]));
      ret = TC_Combine_Sigs_P1(tcsigs, tcinds[0], hM, proof, i, &(wexps[i]), &(sets[i]));
      assert(ret, TC_NOERROR, "TC_Combine_Sigs_P1");
    }
    
    // Phase 2: combine k partial exponents of w, and finally the signature 
    ret = TC_Combine_Sigs_P2(tcinds[0], hM, &csig, wexps, sets[0]);
    assert(ret, TC_NOERROR, "TC_Combine_Sigs_P2");

    // Neither wexps nor wexps[i] is freed within TC_Combine_Sig_P2 
    for (i=0; i<k; i++) {
      BN_free(&(wexps[i]));
    }
    free(wexps);
     
    // In a truly parallel setting, each node invokes TC_Combine_Sig_P2, which frees
    // Set_S internally. No need to free sets[i] as follows.
    for (i=1; i<k; i++) {
      OPENSSL_free(sets[i]);
    }
    
    free(sets);

  } else {
    if (proof) {
      // Explicitly check a proof 
      ret = TC_Check_Proof(tcinds[0], hM, tcsigs[0], 1);
      assert(ret, 1, "TC_Check_Proof");
    }
    
    // Directly combine all individual signatures
    ret = TC_Combine_Sigs(tcsigs, tcinds[0], hM, &csig, proof);
    assert(ret, TC_NOERROR, "TC_Combine_Sigs");
  }

  tcpk = TC_get_pub(tcd);

  // Verify combined signature
  ret = TC_verify(hM, csig, tcpk);
  assert(ret, 1, "TC_verify");

  // Cleanup
  TC_PK_free(tcpk);
    
  for (i=0; i<n; i++) {
    TC_IND_free(tcinds[i]);
  }
    
  TC_DEALER_free(tcd);
  
  TC_SIG_Array_free(tcsigs, n);
  TC_IND_SIG_free(sig);
  free(tcinds);

  BN_free(csig);
  BN_free(hM);
}

int main(int argc, char **argv)
{
  int keysize, faults, proof, partial_combine;
    
  if (argc != 5) {
    fprintf(stderr, "Usage: %s keysize #faults proof partial_combine\n", argv[0]);
    exit(1);
  }

  keysize = atoi(argv[1]);
  if (keysize != 256 && keysize != 512 && keysize != 1024 && keysize != 2048) {
    fprintf(stderr, "Invalid keysize. keysize should be 256/512/1024/2048.\n");
    exit(1);
  }
  
  faults = atoi(argv[2]);
  if (faults < 1) {
    fprintf(stderr, "Invalid #faults.\n");
    exit(1);
  }

  proof = atoi(argv[3]);
  if (proof < 0 || proof > 1) {
    fprintf(stderr, "Invalid proof. proof should be in [0..1].\n");
    exit(1);
  }

  partial_combine = atoi(argv[4]);
  if (partial_combine < 0 || partial_combine > 1) {
    fprintf(stderr, "Invalid partial_combine. partial_combine should be in [0..1].\n");
    exit(1);
  }
  
  srandom(time(NULL));
  test(keysize, faults, proof, partial_combine);

  return 0;
}
