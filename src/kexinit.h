/* kexinit.h
 *
 * Handling of KEXINIT messages and algorithm selection.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Niels Möller
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

#ifndef LSH_KEXINIT_H_INCLUDED
#define LSH_KEXINIT_H_INCLUDED

#include "alist.h"
#include "abstract_crypto.h"
#include "compress.h"
#include "list.h"

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
# include "kexinit.h.x"
#undef GABA_DECLARE

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
       (make method (object kexinit)) ))
*/

#define MAKE_KEXINIT(s) ((s)->make((s)))

/* GABA:
   (struct
     (name kexinit_state)
     (vars
       (state . "enum kex_state")

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

struct kexinit *
parse_kexinit(struct lsh_string *packet);
     
struct lsh_string *
format_kexinit(struct kexinit *kex);

/* Returns NULL on success, otherwise an error message. */
const char *
handle_kexinit(struct kexinit_state *self, struct lsh_string *packet,
	       struct alist *algorithms, int mode);

struct hash_instance *
kex_build_secret(const struct hash_algorithm *H,
		 struct lsh_string *exchange_hash,
		 struct lsh_string *K);

int
kex_make_encrypt(struct crypto_instance **c,
		 struct hash_instance *secret,
		 struct object_list *algorithms,
		 int type,
		 struct lsh_string *session_id);

int
kex_make_decrypt(struct crypto_instance **c,
		 struct hash_instance *secret,
		 struct object_list *algorithms,
		 int type,
		 struct lsh_string *session_id);

struct mac_instance *
kex_make_mac(struct hash_instance *secret,
	     struct object_list *algorithms,
	     int type,
	     struct lsh_string *session_id);

struct compress_instance *
kex_make_deflate(struct object_list *algorithms,
		 int type);

struct compress_instance *
kex_make_inflate(struct object_list *algorithms,
		 int type);

#endif /* LSH_KEXINIT_H_INCLUDED */
