*************************************
* Steward Overview and Instructions *
*************************************

Steward is a hierarchical Byzantine fault tolerant replication system.  The
system is typically configured as follows: Physical machines (servers) are
placed in several local area sites distributed across a wide area network.
Steward is designed to work well in environments where the local area bandwidth
is relatively large compared to the wide-area bandwidth.  The servers in each
site emulate a single logical entitiy which participates in a wide-area
state-machine replication protocol.  Each site can sustain f or fewer Byzantine
faults (i.e., malicious servers) before being compromised.  The system requires
that at least a majority of correct sites are connected in order to make
progress.  Safety is guaranteed only when no sites are compromised (i.e., there
can be at most f failures in a site).

Steward is the first generation hierachical state-machine replication system
constructed by the Distributed Systems and Networking Lab at Johns Hopkins
University and by the Dependable and Secure Distributed Systems Laboratory at
Purdue University.  It underwent a succesful Red Team evaluation in 2006.
However, this code is a prototype and is intended only to demonstrate
feasibility and potential performance benefits.  It is not intended to be used
for purposes other than research.  Note that the release system does not use
aggregation and cryptography optimizations that are described in the paper:

Y. Amir, B. Coan, J. Kirsch, J. Lane. Customizable Fault Tolerance for 
Wide-Area Replication.  In Proceedings of the 26th IEEE International 
Symposium on Reliable Distributed Systems (SRDS 2007), Beijing, China, 2007, 
pp. 66-80.

Both of these optimizations can dramatically improve system performance.  In
particular, when wide area bandwidth is limited, Steward becomes
computationally limited because of its use of public-key crytpography
(including threshold cryptography).  This limitation can be circumvented by
amortizing the cost of cryptographic optimiztations using Merkle Trees.  

**************************
* Software Dependencies: *
**************************

Steward uses two cryptography libraries: OpenSSL and OpenTC.  OpenSSL can be
downloaded from www.openssl.org.  OpenTC is a threshold cryptography library
and is included in this release.  The OpenTC license is in the
/OpenTC-1.1/TC-lib-1.0 directory.  The static OpenSSL library is assumed to be
in the crypto_lib directory in the Steward root directory.  Before building
Steward, you can place libcrypto.a (the OpenSSL library) in the crypto_lib
directory.  Otherwise, you must change the Steward make file so that the
library files can be found when Steward is compiled.  

******************
* Configuration: *
******************

Steward contains several configurable parameters.  Steward must be compiled in
order to change these parameters.  The configuration.h header file contains
defintions which can be used to specify the number of sites, the number of
possible faults in each site, and the maximum number of clients in each site.
In addition, Steward can be configured to automatically generate files
containing various types of data (see configuration.h).  

Finally, Steward can be configured so that the non-leader sites are emulated
(for benchmarking). 

The bin directory contains a sample address configuration file (address.config)
which tell the servers the ip addresses of the other servers based on server id
and site.  The file contains a line for each server with the following format:

site_id server_id ip_address

The site_id is an integer from 1 to the number of sites. The server_id is a
number from 1 to the number of servers in each site. The ip_address is a
standard dotted ipv4 address.

NOTE: THE CONFIG FILE MUST BE WRITTEN TO MATCH THE PARAMETERS SPECIFIED IN THE
configuration.h FILE. The sample address.config file contains entries for a
system with five sites, each containing 4 servers.  

**************
* Compiling: *
**************

Steward can be compiled by typing make in the root directory.  Three
executables will be generated and stored in the /bin subdirectory.  The
programs are gen_keys, server and client. 

***********
* To run: *
***********

The following assumes that you have successfully compiled the server and client
and carried out the necesary configuration steps discussed above. The servers
can be run as follows:

First make sure you are in the ./bin driectory inside of the Steward directory.

The gen_keys program must be run first:

./gen_keys

This generate keys for the servers and clients, including keys for threshold
cryptography.  The keys are stored in bin/keys.  The server and client programs
must read the keys from the ./keys directory.  We assume that in a secure
deployment the private keys are accessible only to the server to which they
belong.
 
Then, the server can be run as follows:

./server -s SITE_ID -i SERVER_ID

Where SITE_ID denotes an integer from 1 to the number of sites and SERVER_ID
denotes an integer from 1 to the number of servers in each site.

If you have not selected to use emulation, all of the servers should be
executed. 

The client can be run like this:

./client -s SITE_ID -i CLIENT_ID -l IP_ADDRESS

Where SITE_ID denotes an integer from 1 to the number of sites, CLIENT_ID
denotes an integer from 1 to the maximum number of clients per site, and
IP_ADDRESS denotes the ip address of the client program.  One or more clients
can be run. 

****************
* Output files *
****************

Steward can output several different types of files.  The files that Steward
produces can be selected at compile time by changing the configuration.h file.
In this section, we describe the contents of some of the output files.

STATE_MACHINE Output: Each server outputs a file having the name
state_machine_out.SITE_ID_SERVER_ID.log. This files contains an entry for each
ordered update that has been applied to the state machine at the server.
Steward provides a total order on all updates injected into the system.
Therefore, the files should be consistent. Note that it is possible that the
different servers have ordered different numbers of updates. However, all
updates ordered by a server should match any corresponding ordered updates in
all other servers.
 
VALIDATION_FAILURES Output: Each server also stores an entry each time that
validation fails in a file having the name validate_fail.SITE_ID_SERVER_ID.log.
These files store some information about the source and type and size of the
message that failed to validate. NOTE that some of the messages are multicast
and certain servers do not need all of the multicast messages. Therefore, the
validate function fails on some signature share messages.

THROUGHPUT Output: 

LATENCY Output: Each client writes a list of latencies, in seconds, of the
requests that it makes in a file having the name latency.SITE_ID_SERVER_ID.log.
The latency is the time difference from when the client submitted a request to
when it received proof that the request was ordered. 

**********************
* Steward Checklist: *
**********************

The following is a short summary of the important things that you must do to
run Steward.

1) Download and compile OpenSSL. Place libcrypto.a in the crypto_lib directory
in the Steward root directory.

2) Decide on the number of sites and number of servers in each site.  Change
the parameters in configuration.h (in Steward/src) accordingly.  Note that the
number of servers in each site is always 3 * NUM_FAULTS + 1.  (NUM_FAULTS is a
parameter in configuration.h)

3) Type make in the Steward/src directory.

4) cd to the Steward/bin directory. Run the gen_keys program: ./gen_keys

5) Change the address.config file as described above.

6) The server and client program can now be run. 

