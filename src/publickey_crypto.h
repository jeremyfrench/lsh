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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_PUBLICKEY_CRYPTO_H_INCLUDED
#define LSH_PUBLICKEY_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"
#include "bignum.h"
#include "connection.h"

#define CLASS_DECLARE
#include "publickey_crypto.h.x"
#undef CLASS_DECLARE

struct signature_algorithm *make_dss_algorithm(struct randomness *random);

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

#if 0
struct group
{
  struct lsh_object header;
  
  /* Returns 1 if x is an element of the group, and is in the
   * canonical representation */
  int (*member)(struct group *closure, mpz_t x);
  void (*invert)(struct group *closure, mpz_t res, mpz_t x);
  void (*combine)(struct group *closure, mpz_t res, mpz_t a, mpz_t b);
  /* FIXME: Doesn't handle negative exponents */
  void (*power)(struct group *closure, mpz_t res, mpz_t g, mpz_t e);
  mpz_t order;
};
#endif

#define GROUP_MEMBER(group, x) ((group)->member((group), (x)))
#define GROUP_INVERT(group, res, x) ((group)->invert((group), (res), (x)))
#define GROUP_COMBINE(group, res, a, b) \
((group)->combine((group), (res), (a), (b)))
#define GROUP_POWER(group, res, g, e) \
((group)->power((group), (res), (g), (e)))

struct group *make_zn(mpz_t p);

/* CLASS:
   (struct
     (name dss_public)
     (vars
       (p bignum)
       (q bignum)
       (g bignum)
       (y bignum)))
*/

/* FIXME: Where are these used? */
#if 0
/* DSS signatures */
struct dss_public
{
  mpz_t p;
  mpz_t q;
  mpz_t g;
  mpz_t y;
};
#endif

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

#if 0
struct diffie_hellman_method
{
  struct lsh_object header;
  
  struct group *G;
  mpz_t generator;
  struct hash_algorithm *H;
  struct randomness *random;
};
#endif

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

#if 0
struct diffie_hellman_instance
{
  struct diffie_hellman_method *method;
  mpz_t e; 			/* client value */
  mpz_t f; 			/* server value */
  struct lsh_string *server_key;
  struct lsh_string *signature;
  mpz_t secret; 		/* This side's secret exponent */
  mpz_t K;
  struct hash_instance *hash;
  struct lsh_string *exchange_hash;
};
#endif

/* Creates client message */
struct lsh_string *dh_make_client_msg(struct diffie_hellman_instance *self);

/* Recieves client message */
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
