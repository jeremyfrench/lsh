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
#include "kexinit.h"
#include "list.h"



#define GABA_DECLARE
#include "keyexchange.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name keyexchange_algorithm)
     (vars
       ;; FIXME: Add some method or attribute describing
       ;; the requirements on the hostkey algorithm.

       ; Algorithms is an array indexed by the KEX_* values above
       (init method void
	     "struct ssh_connection *connection"
	     "int hostkey_algorithm_atom"
	     "struct lsh_object *extra"
	     "struct object_list *algorithms")))
*/

#define KEYEXCHANGE_INIT(kex, connection, ha, e, a) \
((kex)->init((kex), (connection), (ha), (e), (a)))

     
void disconnect_kex_failed(struct ssh_connection *connection, const char *msg);


struct make_kexinit *
make_simple_kexinit(struct randomness *r,
		    struct int_list *kex_algorithms,
		    struct int_list *hostkey_algorithms,
		    struct int_list *crypto_algorithms,
		    struct int_list *mac_algorithms,
		    struct int_list *compression_algorithms,
		    struct int_list *languages);


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

void
keyexchange_finish(struct ssh_connection *connection,
		   struct object_list *algorithms,
		   const struct hash_algorithm *H,
		   struct lsh_string *exchange_hash,
		   struct lsh_string *K);

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
