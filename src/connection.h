/* connection.h
 *
 */

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "lsh_types.h"
#include "abstract_io.h"

struct ssh_connection
{
  struct abstract_write super;
  
  /* Sent and recieved version strings */
  struct lsh_string *client_version;
  struct lsh_string *server_version;

  struct lsh_string *session_id;
  struct abstract_write *raw;   /* Socket connected to the other end */

  struct abstract_write *write; /* Where to send packets through the
				 * pipeline */

  /* Table of all known message types */
  struct abstract_write *dispatch[0x100];

  UINT32 max_packet;

  /* Key exchange */
  struct kexinit *recieved_kexinit;
  struct kexinit *sent_kexinit;

  int provides_privacy;
  int provides_integrity;
};

struct ssh_connection *ssh_connection_alloc();

struct connection_closure
{
  struct abstract_write super;
  struct connection *connection;
};

#if 0
struct abstract_write *make_unimplemented(struct connection *c);  
#endif

#endif /* LSH_CONNECTION_H_INCLUDED */
