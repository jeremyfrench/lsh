/* connection.h
 *
 */

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "abstract_io.h"
#include "randomness.h"

/* Forward declaration */
struct ssh_connection;

/* This is almost a write handler; difference is that it gets an extra
 * argument with a connection object. */

struct packet_handler
{
  struct lsh_object header;
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
  
#if 0
  int type; /* CONNECTION_SERVER or CONNECTION_CLIENT */
#endif
  
  /* Sent and recieved version strings */
  struct lsh_string *client_version;
  struct lsh_string *server_version;

  struct lsh_string *session_id;

  /* Recieveing */
  UINT32 rec_max_packet;
  struct mac_instance *rec_mac;
  struct crypto_instance *rec_crypto;

  /* Sending */
  struct abstract_write *raw;   /* Socket connected to the other end */

  struct abstract_write *write; /* Where to send packets through the
				 * pipeline */

  struct mac_instance *send_mac;
  struct crypto_instance *send_crypto;

  /* Key exchange */
  int kex_state;
  
#if 0
  struct make_kexinit *make_kexinit;
#endif

  /* First element is the kexinit sent by the server */
  struct kexinit *kexinits[2];
  struct lsh_string *literal_kexinits[2];
  struct newkeys_info *newkeys; /* Negotiated algorithms */ 
  
  /* Table of all known message types */
  struct packet_handler *dispatch[0x100];

  /* Shared handlers */
  struct packet_handler *ignore;
  struct packet_handler *unimplemented;
  struct packet_handler *fail;
  
#if 0  
  int provides_privacy;
  int provides_integrity;
#endif
};

struct ssh_connection *make_ssh_connection(struct packet_handler *kex_handler);
void connection_init_io(struct ssh_connection *connection,
			struct abstract_write *raw,
			struct randomness *r);

struct packet_handler *make_fail_handler(void);
struct packet_handler *make_unimplemented_handler(void);  

#endif /* LSH_CONNECTION_H_INCLUDED */
