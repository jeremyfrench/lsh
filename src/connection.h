/* connection.h
 *
 */

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "lsh_types.h"

struct ssh_connection
{
  /* Sent and recieved version strings */
  struct lsh_string *client_version;
  struct lsh_string *server_version;

  struct lsh_string *session_id;
  struct abstract_write *write;   /* Socket connected to the other end */

  UINT32 max_packet;
  
  int provides_privacy;
  int provides_integrity;
};

struct ssh_connection *ssh_connection_alloc();

#endif /* LSH_CONNECTION_H_INCLUDED */
