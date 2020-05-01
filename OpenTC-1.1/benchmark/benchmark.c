#include <time.h>
#include <sys/time.h>
#include "TC.h"
#include "sampling.h"

#define T_DEALER          0
#define T_GENIND_NOPROOF  1
#define T_GENIND          2
#define T_COMBINE_NOPROOF 3
#define T_COMBINE         4
#define T_CHECK_PROOF     5
#define T_VERIFY          6
#define NTIMERS           7

void sampling(int keysize, int faults, int nsamples) {
  double t[NTIMERS];
  
  struct timeval st, ed;

  TC_DEALER *tcd;
  TC_IND **tcinds;
  TC_IND_SIG **tcsigs;
  TC_IND_SIG *sig;
  TC_SIG csig;
  TC_PK *tcpk;
  int n, k;
  int loopidx, i, ret;
  BIGNUM *hM;
  
  // RAND_seed();
  
  n = 3*faults+1;
  k = 3*faults;

  printf("keysize = %d, #faults = %d, n = %d, k = %d, #samples = %d\n",
         keysize, faults, n, k, nsamples);

  hM = BN_new();
  BN_set_word(hM, random());

  tcinds = (TC_IND**) malloc(n*sizeof(TC_IND*));
  tcsigs = TC_SIG_Array_new(n);
  sig = TC_IND_SIG_new();

  LOOP(i, NTIMERS) {
    t[i] = 0; 
  }
  
  LOOP_NSAMPLES(loopidx) {

    // Dealer
    BENCHMARK(t[T_DEALER], st, ed, {
        tcd = TC_generate(keysize/2, n, k, 3);
      });
    
    LOOP(i, n) {
      tcinds[i] = TC_get_ind(i+1, tcd);
    }

    // ------------------------------------------------------------
    // PROOF VERSION HERE
    
    // Generate individual signatures with proofs
    LOOP(i, n) {
      START_TIME(st);
      ret = genIndSig(tcinds[i], hM, sig, 1);
      END_TIME(ed);
      ASSERT(ret, TC_NOERROR, "genIndSig:1");
      
      set_TC_SIG(i+1, sig, tcsigs);
      if (i == 0) {
        SUM_ELAPSED(t[T_GENIND], st, ed);
      }
    }

    // Check proof
    {
      TC_IND_SIG **ind_sigs = tcsigs;
      TC_IND *key = tcinds[0];

      BENCHMARK(t[T_CHECK_PROOF], st, ed, {
          ret = TC_Check_Proof(key, hM, ind_sigs[0], 1);
        });
      ASSERT(ret, 1, "TC_Check_Proof");
    }

    // Combine individual sigatures with checking proofs
    BENCHMARK(t[T_COMBINE], st, ed, {
        ret = TC_Combine_Sigs(tcsigs, tcinds[0], hM, &csig, 1);
      });
    ASSERT(ret, TC_NOERROR, "TC_Combine_Sigs:1");
    
    tcpk = TC_get_pub(tcd);

    // Verify combined signature
    BENCHMARK(t[T_VERIFY], st, ed, {
        ret = TC_verify(hM, csig, tcpk);
      });
    ASSERT(ret, 1, "TC_verify");

    TC_PK_free(tcpk);

    // ------------------------------------------------------------
    // NO PROOF VERSION HERE
    
    // Generate individual signatures without proofs
    LOOP(i, n) {
      START_TIME(st);
      ret = genIndSig(tcinds[i], hM, sig, 0);
      END_TIME(ed);
      ASSERT(ret, TC_NOERROR, "genIndSig:0");
      
      set_TC_SIG(i+1, sig, tcsigs);
      if (i == 0) {
        SUM_ELAPSED(t[T_GENIND_NOPROOF], st, ed);
      }
    }

    // Combine individual sigatures without checking proofs
    BENCHMARK(t[T_COMBINE_NOPROOF], st, ed, {
        ret = TC_Combine_Sigs(tcsigs, tcinds[0], hM, &csig, 0);
      });
    ASSERT(ret, TC_NOERROR, "TC_Combine_Sigs:0");
    
    tcpk = TC_get_pub(tcd);

    // Verify combined signature
    ret = TC_verify(hM, csig, tcpk);
    ASSERT(ret, 1, "TC_verify");

    TC_PK_free(tcpk);
    
    // ------------------------------------------------------------
    
    LOOP(i, n) {
      TC_IND_free(tcinds[i]);
    }
    
    TC_DEALER_free(tcd);

    printf(".");
    fflush(stdout);
  }
  printf("\n");

  LOOP(i, NTIMERS) {
    AVG_NSAMPLES(t[i]);
  }

  PRINT_TIME("TC_generate",               t[T_DEALER]);
  PRINT_TIME("genIndSig w/o proof",       t[T_GENIND_NOPROOF]);
  PRINT_TIME("genIndSig",                 t[T_GENIND]);
  PRINT_TIME("TC_Combine_Sigs w/o proof", t[T_COMBINE_NOPROOF]);
  PRINT_TIME("TC_Combine_Sigs",           t[T_COMBINE]);
  PRINT_TIME("TC_Check_Proof",            t[T_CHECK_PROOF]);
  PRINT_TIME("TC_verify",                 t[T_VERIFY]);
  
  printf("%d\t%d\t%d\t%d\t%d"
         "\t%lf\t%lf\t%lf\t%lf"
         "\t%lf\t%lf\t%lf"
         "\n",
         keysize, faults, n, k, nsamples,
         t[0], t[1], t[2], t[3],
         t[4], t[5], t[6]);
  
  TC_SIG_Array_free(tcsigs, n);
  TC_IND_SIG_free(sig);
  free(tcinds);

  BN_free(hM);
}

int main(int argc, char **argv)
{
  int nsamples;
  int keysize, faults;
    
  if (argc != 4) {
    fprintf(stderr, "Usage: %s keysize #faults #samples\n", argv[0]);
    exit(1);
  }

  keysize = atoi(argv[1]);
  if (keysize != 256 && keysize != 512 && keysize != 1024 && keysize != 2048) {
    fprintf(stderr, "Invalid keysize.\n");
    exit(1);
  }
  
  faults = atoi(argv[2]);
  if (faults < 1) {
    fprintf(stderr, "Invalid #faults.\n");
    exit(1);
  }

  nsamples = atoi(argv[3]);
  if (nsamples < 1) {
    fprintf(stderr, "Invalid #samples.\n");
    exit(1);
  }
  
  srandom(time(NULL));
  sampling(keysize, faults, nsamples);

  return 0;
}
