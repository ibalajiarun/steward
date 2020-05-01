CC = gcc
CFLAGS = -Wall -O2
INCDIR = . 
LIBDIR = .

all: benchmark
benchmark:	benchmark.c
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(LIBDIR)/libTC.a -o $@ -lssl

clean:
	$(RM) *.o benchmark
