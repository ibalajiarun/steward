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

#include "query_protocol.h"
#include "utility.h"
#include "util/alarm.h"
#include "util/memory.h"

extern server_variables VAR;
int32u query_count = 0;

signed_message* New_Response_Message( int32u machine_id, signed_message
       *query ) {

  signed_message          *response;
  query_message           *query_specific;
  client_response_message *response_specific;

    if ( UTIL_I_Am_In_Leader_Site() ) {
	machine_id = VAR.My_Server_ID;
    }

  response          = UTIL_New_Signed_Message();
  response_specific = (client_response_message *)(response+1);

  response->type       = CLIENT_QUERY_RESPONSE_TYPE;
  response->len        = sizeof(client_response_message);
  response->site_id    = VAR.My_Site_ID;
  response->machine_id = machine_id;

  query_specific = (query_message *)(query+1);

  response_specific->time_stamp = query_specific->time_stamp;

  /* Sign the response. */
  if ( UTIL_I_Am_In_Leader_Site() || machine_id == 1 ) {
    UTIL_RSA_Sign_Message(response);
  }

  return response;

}

void Query_Handler(signed_message *query)
{
  signed_message          *response;
  query_message           *query_specific;
  //client_response_message *response_specific;

#if EMULATE_NON_REP_SITE
  int32u i;
#endif

  response = New_Response_Message( VAR.My_Server_ID, query ); 

  query_specific = (query_message *)(query+1);

  Alarm(DEBUG, "Query_Handler\n");

#if EMULATE_NON_REP_SITE
  if ( 1 ) { //UTIL_I_Am_In_Leader_Site() ) {
    UTIL_Send_To_Client(query_specific->address, query->site_id, 
		      query->machine_id, response);
  } else {    
      for(i = 1; i <= NUM_FAULTS+1; i++) {
	response->machine_id = i;
	//UTIL_Busy_Wait(0.001);
	Alarm(DEBUG,"%d %d %d %d "IPF"\n", VAR.My_Site_ID, VAR.My_Server_ID,
	  query->site_id, query->machine_id, IP(query_specific->address) ); 
	UTIL_Send_To_Client(query_specific->address, query->site_id, 
			    query->machine_id, response);
      }
  }
#else
  UTIL_Send_To_Client(query_specific->address, query->site_id, 
		      query->machine_id, response);
#endif  

  dec_ref_cnt(response);

  query_count++;

  /* For benchmarks */
  if(query_count == 5000) {
    Alarm(EXIT, "Finished 5000 queries.\n");
  }
}
