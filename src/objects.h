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

#ifndef OBJECTS_H
#define OBJECTS_H

#define MAX_OBJECTS             200
#define MAX_OBJ_USED            (UNKNOWN_OBJ+1)

/* Object types 
 *
 * Object types must start with 1 and go up. 0 is reserved 
 */


/* Util objects */
#define BASE_OBJ                1
#define TIME_EVENT              2
#define QUEUE                   3
#define QUEUE_SET               4
#define QUEUE_ELEMENT           5
#define MQUEUE_ELEMENT          6
#define SCATTER                 7
#define SYS_SCATTER             8

/* Sent objects */
#define PACK_BODY_OBJ           9
#define PACK_HEAD_OBJ           10

/* Local objects */
#define GLOBAL_SLOT_OBJ		11
#define PENDING_SLOT_OBJ        12
#define DLL_NODE_OBJ	        13

/* CCS Union object*/
#define UNION_ENTRY_OBJ         14

/* Special objects */
#define UNKNOWN_OBJ             15      /* This should be the last one */ 

/* Global Functions to manipulate objects */
int     Is_Valid_Object(int32u oid);
char    *Objnum_to_String(int32u obj_type);

#endif /* OBJECTS_H */


