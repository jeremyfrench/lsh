/* lookup_verifier.h
 *
 * Lookup signature verifiers of a public key
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balazs Scheidler
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

#ifndef LSH_LOOKUP_VERIFIER_H_INCLUDED
#define LSH_LOOKUP_VERIFIER_H_INCLUDED

#include "lsh.h"
#include "abstract_crypto.h"

#define GABA_DECLARE
#include "lookup_verifier.h.x"
#undef GABA_DECLARE

/* Maps a key blob to a signature verifier, using some signature
 * algorithm and some method to determine the authenticity of the key.
 * Returns NULL If the key is invalid or not trusted. */

/* FIXME: Does this function really need the keyholder? On the client
 * side, the client ought to know which host it is trying to connect
 * to. What about the server side? There the action has to depends on
 * the user. But there, a struct unix_user is probably more
 * appropriate than a user name alone. */

/* GABA:
   (class
     (name lookup_verifier)
     (vars
       (lookup method (object verifier)
                      "struct lsh_string *keyholder"
		      "struct lsh_string *key")))
*/

#define LOOKUP_VERIFIER(l, kh, key) ((l)->lookup((l), (kh), (key)))

#endif /* LSH_LOOKUP_VERIFIER_H_INCLUDED */
