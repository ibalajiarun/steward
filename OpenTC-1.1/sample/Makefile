CC = gcc
CFLAGS = -Wall -Wunused 
INCDIR = . 
LIBDIR = ../TC-lib-1.0/.libs/

all: sample create read
sample:	sample.c
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(LIBDIR)/libTC.a -o $@ -lssl

read:	readSample.c
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(LIBDIR)/libTC.a -o $@ -lssl

create: create_share_files.c
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(LIBDIR)/libTC.a -o $@ -lssl

clean:
	$(RM) *.o sample create read
