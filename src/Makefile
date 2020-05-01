#
# Steward.
#     
# The contents of this file are subject to the Steward Open-Source
# License, Version 1.0 (the ``License''); you may not use
# this file except in compliance with the License.  You may obtain a
# copy of the License at:
#
# http://www.dsn.jhu.edu/byzrep/steward/LICENSE.txt
#
# or in the file ``LICENSE.txt'' found in this distribution.
#
# Software distributed under the License is distributed on an AS IS basis, 
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
# for the specific language governing rights and limitations under the 
# License.
#
# The Creators of Steward are:
#  Yair Amir, Claudiu Danilov, Danny Dolev, Jonathan Kirsch, John Lane,
#  Cristina Nita-Rotaru, Josh Olsen, and David Zage.
#
# Copyright (c) 2005 - 2010 
# The Johns Hopkins University, Purdue University, The Hebrew University.
# All rights reserved.
#

# Steward Make File 

CC = gcc 

# Spines (an overlay network developed at Johns Hopkins) can be used to aid in
# the emulation of Steward. Steward was originally benchmarked using Spines to
# add latency between local area sites and to limit bandwidth between local
# area sites. However, we have recently used netem instead of Spines during
# benchmarking, and we recommend compiling Steward without Spines and using
# netem to add latency and to constrain bandwidth.
 
# Comment out SPINES and SPINES_LIB to compile without spines
#SPINES = -DSET_USE_SPINES
#SPINES_LIB = spines/spines_lib.a

# Location of the openssl library
# OPENSSL_LIB = ../crypto_lib/libcrypto.a
OPENSSL_LIB = -l:libcrypto.a -ldl 
# location od the OpenTC threhold cryptography library
TC_LIB = ../OpenTC-1.1/TC-lib-1.0/.libs/libTC.a

INC = -I ../crypto_lib -I ../stdutil/src
STDUTIL_LIB = ../stdutil/lib/libstdutil.a

OBJECTS = $(UTIL_OBJ) $(WRAPPER_OBJ) $(DATA_OBJ) $(PROT_OBJ) srv.o network.o

A_OBJECTS = $(UTIL_OBJ) $(WRAPPER_OBJ) $(DATA_OBJ) $(PROT_OBJ) attack.o network.o

CLI_OBJECTS = $(UTIL_OBJ) $(WRAPPER_OBJ) $(DATA_OBJ) $(PROT_OBJ) client.o

GEN_KEYS_OBJECTS = $(UTIL_OBJ) $(WRAPPER_OBJ) $(DATA_OBJ) $(PROT_OBJ) 

UTIL_OBJ = util/alarm.o util/events.o util/memory.o util/data_link.o

WRAPPER_OBJ = error_wrapper.o tc_wrapper.o openssl_rsa.o
  
DATA_OBJ = data_structs.o utility.o apply.o 

PROT_OBJ = validate.o dispatcher.o rep_election.o assign_sequence.o \
	   threshold_sign.o local_reconciliation.o ordered_receiver.o \
	   prepare_certificate_receiver.o meta_globally_order.o \
	   conflict.o global_view_change.o construct_collective_state_protocol.o construct_collective_state_util.o \
	   query_protocol.o \
	   global_reconciliation.o

CFLAGS = -g -Wall -O2 $(SPINES) $(INC)  

all: $(TC_LIB) $(STDUTIL_LIB) server client gen_keys

$(TC_LIB):
	cd ../OpenTC-1.1/TC-lib-1.0/; ./configure; make

$(STDUTIL_LIB):
	cd ../stdutil; make

gen_keys: openssl_rsa.o generate_keys.c
	$(CC) -o ../bin/$@ generate_keys.c $(GEN_KEYS_OBJECTS) $(EXTRALIBS) $(TC_LIB) $(STDUTIL_LIB) $(SPINES_LIB) $(OPENSSL_LIB)  

server: $(OBJECTS)
	$(CC) $(CFLAGS) -o ../bin/server $(OBJECTS) $(EXTRALIBS) $(TC_LIB) $(STDUTIL_LIB) $(SPINES_LIB) $(OPENSSL_LIB)

attack: $(A_OBJECTS)
	$(CC) $(CFLAGS) -o ../bin/attack $(A_OBJECTS) $(EXTRALIBS) $(TC_LIB) $(STDUTIL_LIB) $(SPINES_LIB) $(OPENSSL_LIB)

client: $(CLI_OBJECTS)
	$(CC) -o ../bin/client $(CLI_OBJECTS) $(EXTRALIBS) $(TC_LIB) $(STDUTIL_LIB) $(SPINES_LIB) $(OPENSSL_LIB)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $*.o $*.c

clean:
	rm -f *~
	rm -f *.o
	rm -f util/*~
	rm -f util/*.o
	rm -f core*
	rm -f ../bin/server
	rm -f ../bin/client
	rm -f ../bin/gen_keys
	rm -f ../bin/attack

distclean: clean
	cd ../stdutil; make distclean
	cd ../OpenTC-1.1/TC-lib-1.0/; make distclean
	cd ../bin/keys; rm -f *.pem; rm -f *.key
	
