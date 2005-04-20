/* keyexchange.h
 *
 */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_KEYEXCHANGE_H_INCLUDED
#define LSH_KEYEXCHANGE_H_INCLUDED

#include "abstract_crypto.h"
#include "alist.h"
#include "compress.h"
#include "list.h"

struct transport_connection;

/* State affecting incoming keyexchange packets */
enum kex_state
{
  /* A KEX_INIT can be accepted. This is true most of the time. */
  KEX_STATE_INIT,

  /* Ignore next packet, whatever it is. */
  KEX_STATE_IGNORE,

  /* Key exchange is in progress. Neither KEX_INIT or NEWKEYS
     messages, nor upper-level messages can be received. */
  KEX_STATE_IN_PROGRESS,

  /* Key exchange is finished. A NEWKEYS message should be received.
     Besides NEWKEYS, only DISCONNECT, IGNORE and DEBUG are
     acceptable. */
  KEX_STATE_NEWKEYS
};

enum
{
  KEX_ENCRYPTION_CLIENT_TO_SERVER = 0,
  KEX_ENCRYPTION_SERVER_TO_CLIENT = 1,
  KEX_MAC_CLIENT_TO_SERVER = 2,
  KEX_MAC_SERVER_TO_CLIENT = 3,
  KEX_COMPRESSION_CLIENT_TO_SERVER = 4,
  KEX_COMPRESSION_SERVER_TO_CLIENT = 5,
  
  KEX_PARAMETERS = 6,

  KEX_KEY_EXCHANGE = 6,
  KEX_LIST_LENGTH = 7
};

#define GABA_DECLARE
#include "keyexchange.h.x"
#undef GABA_DECLARE

/* GABA:
   (struct
     (name kexinit_state)
     (vars
       (read_state . "enum kex_state")
       ; Non-zero if we have sent KEXINIT but not NEWKEYS
       (write_state . int)
       ; Client is index 0, server is index 1.
       (version array (string) 2)
       (kexinit array (object kexinit) 2)
       (literal_kexinit array (string) 2)

       ; Output of the algorithm negotiation
       (hostkey_algorithm . int)
       ; The selected algorithms, indexed by 0...KEX_KEY_EXCHANGE
       (algorithm_list object object_list)))
*/

void
init_kexinit_state(struct kexinit_state *self);

void
reset_kexinit_state(struct kexinit_state *self);

struct lsh_string *
format_kexinit(struct kexinit *kex);

/* Returns NULL on success, otherwise an error message. */
const char *
handle_kexinit(struct kexinit_state *self,
	       uint32_t length, const uint8_t *packet,
	       struct alist *algorithms, int is_server);


/* GABA:
   (class
     (name keyexchange_algorithm)
     (vars
       ;; FIXME: Add some method or attribute describing
       ;; the requirements on the hostkey algorithm.

       ; Algorithms is an array indexed by the KEX_* values above
       (init method (object transport_handler)
	     "struct randomness *random"
	     "struct kexinit_state *kex")))
*/

#define KEYEXCHANGE_INIT(kex, random, s) \
((kex)->init((kex), (random), (s)))

/* GABA:
   (class
     (name kexinit)
     (vars
       (cookie array uint8_t 16);
       ; Lists of atoms
       (kex_algorithms object int_list)
       (server_hostkey_algorithms object int_list)
       (parameters array (object int_list) KEX_PARAMETERS)
       (languages_client_to_server object int_list)
       (languages_server_to_client object int_list)
       (first_kex_packet_follows . int)
       ; May be NULL. Used only for sending.
       (first_kex_packet string)))
*/
     
/* This function generates a new kexinit message.
 *
 * If a speculative packet follows, it is stored in the last field. */

/* GABA:
   (class
     (name make_kexinit)
     (vars
       (make method (object kexinit) "struct randomness *random")))
*/

#define MAKE_KEXINIT(s, r) ((s)->make((s), (r)))

struct make_kexinit *
make_simple_kexinit(struct int_list *kex_algorithms,
		    struct int_list *hostkey_algorithms,
		    struct int_list *crypto_algorithms,
		    struct int_list *mac_algorithms,
		    struct int_list *compression_algorithms,
		    struct int_list *languages);

struct keyexchange_algorithm *
make_server_dh_group1_sha1(struct alist *keys);

struct keyexchange_algorithm *
make_server_dh_group14_sha1(struct alist *keys);

#if 0

/* Sends the keyexchange message, which must already be stored in
 * connection->kexinits[connection->flags & CONNECTION_MODE]
 */
void send_kexinit(struct ssh_connection *connection);

struct packet_handler *
make_kexinit_handler(struct lsh_object *extra,
		     struct alist *algorithms);

struct packet_handler *
make_newkeys_handler(struct crypto_instance *crypto,
		     struct mac_instance *mac,
		     struct compress_instance *compression);
#endif

int
keyexchange_finish(struct transport_connection *connection,
		   const struct hash_algorithm *H,
		   struct lsh_string *exchange_hash,
		   struct lsh_string *K);

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
