/* keyexchange.h
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_KEYEXCHANGE_H_INCLUDED
#define LSH_KEYEXCHANGE_H_INCLUDED

#include "abstract_crypto.h"
#include "abstract_io.h"
#include "alist.h"
#include "connection.h"

#define KEX_ENCRYPTION_CLIENT_TO_SERVER 0
#define KEX_ENCRYPTION_SERVER_TO_CLIENT 1
#define KEX_MAC_CLIENT_TO_SERVER 2
#define KEX_MAC_SERVER_TO_CLIENT 3
#define KEX_COMPRESSION_CLIENT_TO_SERVER 4
#define KEX_COMPRESSION_SERVER_TO_CLIENT 5

#define KEX_PARAMETERS 6

/* A KEX_INIT msg can be accepted. This is true, most of the time. */
#define KEX_STATE_INIT 0

/* Ignore next packet */
#define KEX_STATE_IGNORE 1

/* Key exchange is in progress. Neither KEX_INIT or NEWKEYS messages
 * can be recieved */
#define KEX_STATE_IN_PROGRESS 2

/* Key exchange is finished. A NEWKEYS message should be recieved, and
 * nothing else. */
#define KEX_STATE_NEWKEYS 3

/* algorithms is an array indexed by the KEX_* values above */
struct keyexchange_algorithm
{
  struct lsh_object header;
  
  int (*init)(struct keyexchange_algorithm *closure,
	      struct ssh_connection *connection,
	      int hostkey_algorithm_atom,
	      struct signature_algorithm *hostkey_algorithm,
	      void **algorithms);
};

#define KEYEXCHANGE_INIT(kex, connection, ha, h, a) \
((kex)->init((kex), (connection), (ha), (h), (a)))

struct kexinit
{
  struct lsh_object header;
  
  UINT8 cookie[16];
  /* Zero terminated list of atoms */
  int *kex_algorithms; 
  int *server_hostkey_algorithms;
  int *parameters[KEX_PARAMETERS];
  int *languages_client_to_server;
  int *languages_server_to_client;
  int first_kex_packet_follows;
};

/* This function generates a new kexinit message.
 *
 * FIXME: It could be replaced with a function that does more: Send
 * the message, record it in the connection structure, and possibly
 * send a first guessed message. */

struct make_kexinit
{
  struct kexinit * (*make)(struct make_kexinit *closure);
};

#define MAKE_KEXINIT(m) ((m)->make((m)))

struct handle_kexinit
{
  struct packet_handler super;
  int type;
  
  struct make_kexinit *init;
  
  /* Maps names to algorithms. It's dangerous to lookup random atoms
   * in this table, as not all objects have the same type. This
   * mapping is used only on atoms that have appeared in *both* the
   * client's and the server's list of algorithms (of a certain type),
   * and therefore the remote side can't screw things up. */

  struct alist *algorithms;
};

/* Installs keys for use. */
struct install_keys
{
  struct lsh_object header;
  
  int (*install)(struct install_keys *closure,
		 struct ssh_connection *connection,
		 struct hash_instance *secret);
};

#define INSTALL_KEYS(i, c, s) ((i)->install((i), (c), (s)))

struct newkeys_info
{
  struct lsh_object header;
  
  struct crypto_algorithm *encryption_client_to_server;
  struct crypto_algorithm *encryption_server_to_client;
  struct mac_algorithm *mac_client_to_server;
  struct mac_algorithm *mac_server_to_client;
#if 0
  struct compression_algorithm *compression_client_to_server;
  struct compression_algorithm *compression_server_to_client;
#endif
};


struct packet_handler *make_kexinit_handler();
struct packet_handler *make_newkeys_handler();

struct lsh_string *format_kex(struct kexinit *kex);
int disconnect_kex_failed(struct ssh_connection *connection, char *msg);

struct crypto_instance *kex_make_encrypt(struct hash_instance *secret,
					 void **algorithms,
					 int type,
					 struct ssh_connection *connection);

struct crypto_instance *kex_make_decrypt(struct hash_instance *secret,
					 void **algorithms,
					 int type,
					 struct ssh_connection *connection);

struct mac_instance *kex_make_mac(struct hash_instance *secret,
				  void **algorithms,
				  int type,
				  struct ssh_connection *connection);

struct make_kexinit *make_test_kexinit(struct randomness *r);

int initiate_keyexchange(struct ssh_connection *connection,
			 int type,
			 struct kexinit *kex,
			 struct lsh_string *first_packet);

struct packet_handler *make_kexinit_handler(int type,
					    struct make_kexinit *init,
					    struct alist *algorithms);

struct packet_handler *
make_newkeys_handler(struct crypto_instance *crypto,
		     struct mac_instance *mac);

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
