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

#ifndef	NET_TYPES
#define	NET_TYPES


/* First byte  of the type field in packet_header - Server messages */
/*
 * #define		VIEWCHANGE_TYPE		0x0001
 * #define		NEWVIEW_TYPE		0x0002
 */

/* Second byte - Client messages */
/*
 * #define		SES_UPDATE_TYPE		0x0100
 * #define		SES_QUERY_TYPE		0x0200
 */



#define        SIGLEN                   128 

typedef	char packet[MAX_PACKET_SIZE];

/* The header of each message */
typedef	struct	dummy_pkt_header {
    /* The first three fields should go in front of each message */
    char     sig[SIGLEN]; /* signature of the message */
    int32u   sender_ID;   /* The ID of the sender of the packet */
    int16u   len;         /* length of the packet */
    int16u   type;        /* type of the message  */ 
} pkt_header;



#endif	/* NET_TYPES */
