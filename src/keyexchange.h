/* keyexchange.h
 *
 */

#ifndef LSH_KEYEXCHANGE_H_INCLUDED
#define LSH_KEYEXCHANGE_H_INCLUDED

#include "lsh_types.h"
#include "abstract_io.h"

struct kexinit
{
  UINT8 cookie[16];
  /* Zero terminated list of atoms */
  int *kex_algorithms; 
  int *server_host_key_algorithms;
  int *encryption_algorithms_client_to_server;
  int *encryption_algorithms_server_to_client;
  int *mac_algorithms_client_to_server;
  int *mac_algorithms_server_to_client;
  int *compression_algorithms_client_to_server;
  int *compression_algorithms_server_to_client;
  int *languages_client_to_server;
  int *languages_server_to_client;
  int first_kex_packet_follows;
};

struct handle_kexinit
{
  int (*f)(struct handle_kexinit *closure,
	   struct kexinit *msg);
};

#define HANDLE_KEXINIT(handler, msg) ((handler)->f((handler), (msg)))

struct handle_kexinit_packet
{
  struct abstract_write super;
  struct handle_kexinit *handler;
};

struct abstract_write *make_packet_kexinit(struct handle_kexinit *handler);

#if 0
struct lsh_string *make_keyexinit_packet(struct keyexinit *msg);
#endif

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
