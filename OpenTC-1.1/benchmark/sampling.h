#ifndef _SAMPLING_H
#define _SAMPLING_H

#define MARK_TIME(tv) gettimeofday(&(tv), NULL)
#define START_TIME(st) MARK_TIME(st)
#define END_TIME(ed) MARK_TIME(ed)
#define ELAPSED(st,ed)                                              \
  (((ed).tv_sec-(st).tv_sec)+(((ed).tv_usec-(st).tv_usec)/(double)1000000.0))
#define SUM_ELAPSED(t,st,ed) t += ELAPSED(st,ed)
#define PRINT_TIME(s,t) printf("%-25.25s: %lf s\n", s, t)
#define PRINT_UTIME(s,t) printf("%-25.25s: %lf us\n", s, t*1000000.0)
#define LOOP_NSAMPLES(i) LOOP(i,nsamples)
#define LOOP(i,n) for (i=0; i<n; i++)
#define AVG_NSAMPLES(t) (t /= nsamples)
#define ASSERT(ret, expect, s)                                        \
  {if (ret != expect) fprintf(stderr, "ERROR: %s (%d)\n", s, ret); }

#define BENCHMARK(t, st, ed, prog) \
  { START_TIME(st); prog; END_TIME(ed); SUM_ELAPSED(t, st, ed); }

#endif /* _SAMPLING_H */
