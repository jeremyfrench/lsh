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

struct signature_algorithm *make_dss_algorithm(struct randomness *random);

/* Groups. For now, assume that all group elements are represented by
 * bignums. */
struct group
{
  /* Returns 1 if x is an element of the group, and is in the
   * canonical representation */
  int (*member)(struct group *closure, mpz_t x);
  void (*invert)(struct group *closure, mpz_t res, mpz_t x);
  void (*combine)(struct group *closure, mpz_t res, mpz_t a, mpz_t b);
  /* FIXME: Doesn't handle negative exponents */
  void (*power)(struct group *closure, mpz_t res, mpz_t g, mpz_t e);
  mpz_t order;
};

#define GROUP_MEMBER(group, x) ((group)->member((group), (x)))
#define GROUP_INVERT(group, res, x) ((group)->invert((group), (res), (x)))
#define GROUP_COMBINE(group, res, a, b) \
((group)->combine((group), (res), (a), (b)))
#define GROUP_POWER(group, res, g, e) \
((group)->power((group), (res), (g), (e)))

/* DH key exchange, with authentication */
struct diffie_hellman_method
{
  struct group *G;
  mpz_t generator;
  struct hash_algorithm *H;
  struct randomness *random;
};

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

/* Creates client message */
struct lsh_string *dh_make_client_msg(struct diffie_hellman_instance *self);

/* Recieves client message */
int dh_process_client_msg(struct diffie_hellman_instance *self,
			  struct lsh_string *packet);

/* Should be called with the kex_init messages, client's first */
void dh_hash_update(struct diffie_hellman_instance *self,
		    struct lsh_string *packet);

/* Creates server message */
struct lsh_string *dh_make_server_msg(struct diffie_hellman_instance *self,
				      struct signer *s);

/* Decodes server message, but does not verify its signature */
int dh_process_server_msg(struct diffie_hellman_instance *self,
			  struct lsh_string *packet);

/* Verifies server's signature */
int dh_verify_server_msg(struct diffie_hellman_instance *self,
			 struct verifier *v);
					
#if 0
struct diffie_hellman_method *
make_diffie_hellman_method(struct group *group,
			   struct hash_algorithm *h,
			   struct randomness *r);
#endif

struct diffie_hellman_method *make_dh1(struct randomness *r);

void init_diffie_hellman_instance(struct diffie_hellman_method *m,
				  struct diffie_hellman_instance *self,
				  struct ssh_connection *c);

struct diffie_hellman_instance *
make_diffie_hellman_instance(struct diffie_hellman_method *m,
			     struct ssh_connection *c);

#endif /* LSH_PUBLICKEY_CRYPTO_H_INCLUDED */
