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
#include "list.h"
#include "connection.h"
#include "service.h"

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

#define CLASS_DECLARE
#include "keyexchange.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name keyexchange_algorithm)
     (vars
       ; Algorithms is an array indexed by the KEX_* values above
       (init method int
	     "struct ssh_connection *connection"
	     "struct ssh_service *finished"
	     "int hostkey_algorithm_atom"
	     "struct signature_algorithm *hostkey_algorithm"
	     "struct object_list *algorithms")))
*/

#define KEYEXCHANGE_INIT(kex, connection, f, ha, h, a) \
((kex)->init((kex), (connection), (f), (ha), (h), (a)))

/* CLASS:
   (class
     (name kexinit)
     (vars
       (cookie array UINT8 16);
       ; Lists of atoms
       (kex_algorithms object int_list)
       (server_hostkey_algorithms object int_list)
       (parameters array (object int_list) KEX_PARAMETERS)
       (languages_client_to_server object int_list)
       (languages_server_to_client object int_list)
       (first_kex_packet_follows simple int)))
*/
     
/* This function generates a new kexinit message.
 *
 * FIXME: It could be replaced with a function that does more: Send
 * the message, record it in the connection structure, and possibly
 * send a first guessed message. */

/* CLASS:
   (class
     (name make_kexinit)
     (vars
       (make method (object kexinit))))
*/

#define MAKE_KEXINIT(m) ((m)->make((m)))

/* Installs keys for use. */
/* CLASS:
   (class
     (name install_keys)
     (vars
       (install method int
		"struct ssh_connection *connection"
		"struct hash_instance *secret")))
*/

#define INSTALL_KEYS(i, c, s) ((i)->install((i), (c), (s)))

/* CLASS:
   (class
     (name newkeys_info)
     (vars
       (encryption_client_to_server  object crypto_algorithm)
       (encryption_server_to_client  object crypto_algorithm)
       (mac_client_to_server         object mac_algorithm)
       (mac_server_to_client         object mac_algorithm)
       ;; (compression_client_to_server object compression_algorithm)
       ;; (compression_server_to_client object compression_algorithm)
       ))
*/

struct lsh_string *format_kex(struct kexinit *kex);
int disconnect_kex_failed(struct ssh_connection *connection, const char *msg);

struct crypto_instance *kex_make_encrypt(struct hash_instance *secret,
					 struct object_list *algorithms,
					 int type,
					 struct ssh_connection *connection);

struct crypto_instance *kex_make_decrypt(struct hash_instance *secret,
					 struct object_list *algorithms,
					 int type,
					 struct ssh_connection *connection);

struct mac_instance *kex_make_mac(struct hash_instance *secret,
				  struct object_list *algorithms,
				  int type,
				  struct ssh_connection *connection);

struct make_kexinit *make_simple_kexinit(struct randomness *r,
					 struct int_list *kex_algorithms,
					 struct int_list *hostkey_algorithms,
					 struct int_list *crypto_algorithms,
					 struct int_list *mac_algorithms,
					 struct int_list *compression_algorithms,
					 struct int_list *languages);

struct make_kexinit *make_test_kexinit(struct randomness *r);

int initiate_keyexchange(struct ssh_connection *connection,
			 int type,
			 struct kexinit *kex,
			 struct lsh_string *first_packet);

struct packet_handler *make_kexinit_handler(int type,
					    struct make_kexinit *init,
					    struct alist *algorithms,
					    struct ssh_service *finished);

struct packet_handler *
make_newkeys_handler(struct crypto_instance *crypto,
		     struct mac_instance *mac);

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
