/* publickey_crypto.h
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_PUBLICKEY_CRYPTO_H_INCLUDED
#define LSH_PUBLICKEY_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"
#include "bignum.h"
#include "connection.h"

#define CLASS_DECLARE
#include "publickey_crypto.h.x"
#undef CLASS_DECLARE

struct signature_algorithm *make_dsa_algorithm(struct randomness *random);
#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
struct signer *make_dsa_signer_kludge(struct signer *dsa);
#endif

/* FIXME: Groups could use "non-virtual" methods */

/* Groups. For now, assume that all group elements are represented by
 * bignums. */
/* CLASS:
   (class
     (name group)
     (vars
       (order bignum)
       (member method int "mpz_t x")
       (invert method void "mpz_t res" "mpz_t x")
       (combine method void "mpz_t res" "mpz_t a" "mpz_t b")
       ; FIXME: Doesn't handle negative exponents
       (power method void "mpz_t res" "mpz_t g" "mpz_t e")))
*/

#define GROUP_MEMBER(group, x) ((group)->member((group), (x)))
#define GROUP_INVERT(group, res, x) ((group)->invert((group), (res), (x)))
#define GROUP_COMBINE(group, res, a, b) \
((group)->combine((group), (res), (a), (b)))
#define GROUP_POWER(group, res, g, e) \
((group)->power((group), (res), (g), (e)))

struct group *make_zn(mpz_t p);

/* CLASS:
   (struct
     (name dsa_public)
     (vars
       (p bignum)
       (q bignum)
       (g bignum)
       (y bignum)))
*/

/* DH key exchange, with authentication */
/* CLASS:
   (class
     (name diffie_hellman_method)
     (vars
       (G object group)
       (generator bignum)
       (H object hash_algorithm)
       (random object randomness)))
*/

/* NOTE: Instances are never allocated on the heap by themselves. They
 * are always embedded in other objects. Therefore there's no object
 * header. */

/* CLASS:
   (struct
     (name diffie_hellman_instance)
     (vars
       (method object diffie_hellman_method)
       (e bignum)       ; Client value
       (f bignum)       ; Server value 
       (server_key string)
       (signature string)
       (secret bignum)  ; This side's secret exponent
       (K bignum)
       (hash object hash_instance)
       (exchange_hash string)))
*/

/* Creates client message */
struct lsh_string *dh_make_client_msg(struct diffie_hellman_instance *self);

/* Receives client message */
int dh_process_client_msg(struct diffie_hellman_instance *self,
			  struct lsh_string *packet);

#if 0
/* Should be called with the kex_init messages, client's first */
void dh_hash_update(struct diffie_hellman_instance *self,
		    struct lsh_string *packet);
#endif

/* Generates server's secret exponent */
void dh_make_server_secret(struct diffie_hellman_instance *self);

/* Creates server message */
struct lsh_string *dh_make_server_msg(struct diffie_hellman_instance *self,
				      struct signer *s);

/* Decodes server message, but does not verify its signature */
int dh_process_server_msg(struct diffie_hellman_instance *self,
			  struct lsh_string *packet);

/* Verifies server's signature */
int dh_verify_server_msg(struct diffie_hellman_instance *self,
			 struct verifier *v);

void dh_generate_secret(struct diffie_hellman_instance *self,
			mpz_t r);

void dh_hash_digest(struct diffie_hellman_instance *self, UINT8 *digest);

struct diffie_hellman_method *make_dh1(struct randomness *r);

void init_diffie_hellman_instance(struct diffie_hellman_method *m,
				  struct diffie_hellman_instance *self,
				  struct ssh_connection *c);

#endif /* LSH_PUBLICKEY_CRYPTO_H_INCLUDED */
