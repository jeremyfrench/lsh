/* publickey_crypto.h
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

#ifndef LSH_PUBLICKEY_CRYPTO_H_INCLUDED
#define LSH_PUBLICKEY_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"
#include "parse.h"

#define GABA_DECLARE
#include "publickey_crypto.h.x"
#undef GABA_DECLARE

struct kexinit_state;

/* GABA:
   (class
     (name keypair)
     (vars
       ; Atom identifying algorithm type. Needed mostly to know when to invoke the
       ; ssh2 ssh-dss bug-compatibility kludge. 
       (type . int)
       (public string)
       (private object signer)))
*/

struct keypair *
make_keypair(uint32_t type,
	     struct lsh_string *public,
	     struct signer *private);


/* DH key exchange, with authentication */
/* GABA:
   (class
     (name dh_params)
     (vars
       (limit . uint32_t)
       (modulo bignum)
       ; Generator for the multiplicative group of order modulo - 1
       (generator bignum)
       (H const object hash_algorithm)))
*/

const struct dh_params *
make_dh_params(const char *modulo, unsigned generator,
	       const struct hash_algorithm *H);

const struct dh_params *
make_dh_group1(const struct hash_algorithm *H);

const struct dh_params *
make_dh_group14(const struct hash_algorithm *H);

/* State common for both all DH variants, for both client and
   server. */
/* GABA:
   (struct
     (name dh_state)
     (vars
       (params const object dh_params)
       (e bignum)       ; Client value
       (f bignum)       ; Server value

       (secret bignum)  ; This side's secret exponent

       (hash object hash_instance)
       
       ; Session key
       (K string)
       (exchange_hash string)))
*/

void
init_dh_state(struct dh_state *self,
	      const struct dh_params *params,
	      struct kexinit_state *kex);

void
dh_hash_update(struct dh_state *self,
	       struct lsh_string *s, int free);

void
dh_generate_secret(const struct dh_params *self,
		   struct randomness *random, 
		   mpz_t r, mpz_t v);

void
dh_hash_digest(struct dh_state *self);


/* RSA support */
extern struct signature_algorithm rsa_sha1_algorithm;

/* Non spki keys */
struct verifier *
parse_ssh_rsa_public(struct simple_buffer *buffer);

struct verifier *
make_ssh_rsa_verifier(uint32_t length, const uint8_t *key);


/* DSA signatures */

struct signature_algorithm *
make_dsa_algorithm(struct randomness *random);

/* Non spki keys */
struct verifier *
parse_ssh_dss_public(struct simple_buffer *buffer);

struct verifier *
make_ssh_dss_verifier(uint32_t length, const uint8_t *key);


#endif /* LSH_PUBLICKEY_CRYPTO_H_INCLUDED */
