/* connection.h
 *
 */

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "lsh_types.h"
#include "abstract_io.h"

/* Forward declaration */
struct ssh_connection;

/* This is almost a write handler; difference is that it gets an extra
 * argument with a connection object. */

struct packet_handler
{
  int (*handler)(struct packet_handler *closure,
		 struct ssh_connection *connection,
		 struct lsh_string *packet);
};

#define HANDLE_PACKET(closure, connection, packet) \
((closure)->handler((closure), (connection), (packet)))

#define CONNECTION_SERVER 0
#define CONNECTION_CLIENT 1
     
struct ssh_connection
{
  struct abstract_write super;

  int type; /* CONNECTION_SERVER or CONNECTION_CLIENT */
  
  /* Sent and recieved version strings */
  struct lsh_string *client_version;
  struct lsh_string *server_version;

  struct lsh_string *session_id;
  struct abstract_write *raw;   /* Socket connected to the other end */

  struct abstract_write *write; /* Where to send packets through the
				 * pipeline */

  /* Table of all known message types */
  struct packet_handler *dispatch[0x100];

  /* Shared handlers */
  struct packet_handler *ignore;
  struct packet_handler *unimplemented;
  struct packet_handler *fail;
  
  UINT32 max_packet;

  /* Key exchange */
  int kex_state;
  
  /* First element is the kexinit sent by the server */
  struct kexinit *kexinits[2];
  int ignore_one_packet;
  
  int provides_privacy;
  int provides_integrity;
};

struct ssh_connection *make_ssh_connection(struct packet_handler *kex_handler);

#if 0
struct abstract_write *make_unimplemented(struct connection *c);  
#endif

#endif /* LSH_CONNECTION_H_INCLUDED */
