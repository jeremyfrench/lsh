/* client_keyexchange.h
 *
 * Client specific key exchange handling
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_CLIENT_KEYEXCHANGE_H_INCLUDED
#define LSH_CLIENT_KEYEXCHANGE_H_INCLUDED

#include "keyexchange.h"
#include "publickey_crypto.h"

#define CLASS_DECLARE
#include "client_keyexchange.h.x"
#undef CLASS_DECLARE

/* Maps a key blob to a signature verifier, using some signature
 * algorithm and some method to determine the authenticity of the key.
 * Returns NULL If the key is invalid or not trusted. */

/* FIXME: This function needs the hostname we are connecting to. */

/* CLASS:
   (class
     (name lookup_verifier)
     (vars
       (lookup method (object verifier) "struct lsh_string *key")))
*/

#define LOOKUP_VERIFIER(l, key) ((l)->lookup((l), (key)))

struct keyexchange_algorithm *
make_dh_client(struct diffie_hellman_method *dh,
	       struct lookup_verifier *verifier);

struct install_keys *make_client_install_keys(struct object_list *algorithms);

#endif /* LSH_CLIENT_KEYEXCHANGE_H_INCLUDED */
