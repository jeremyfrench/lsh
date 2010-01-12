/* dh_exchange.c
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "nettle/bignum.h"

#include "crypto.h"

#include "format.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "randomness.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"


const struct dh_params *
make_dh_params(const char *modulo, unsigned generator,
	       const struct nettle_hash *H)
{
  NEW(dh_params, self);
  mpz_init_set_str(self->modulo, modulo, 16);
  mpz_init_set_ui(self->generator, generator);
  self->H = H;
  self->limit = nettle_mpz_sizeinbase_256_u(self->modulo);

  return self;
}

/* The group for diffie-hellman-group1-sha1, also "Well known group 2"
   in RFC 2412. */
const struct dh_params *
make_dh_group1(const struct nettle_hash *H)
{
  /* 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 } */  
  return make_dh_params("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
			"FFFFFFFFFFFFFFFF",
			2, H);
}

/* The group for diffie-hellman-group14-sha1, also "Well known group
   14" in RFC 3526. */
const struct dh_params *
make_dh_group14(const struct nettle_hash *H)
{
  /* 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 } */
  return make_dh_params("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF",
			2, H);
}

/* Consumes the input string. FIXME: Allocating, hashing, and freeing
   the string is somewhat unnecessary. It might make sense with a hash
   update function that takes the same kind of format string as
   ssh_format. */
void
dh_hash_update(struct dh_state *self, struct lsh_string *s)
{
  hash_update(self->hash, STRING_LD(s));
  lsh_string_free(s);
}

/* Hashes e, f, and the shared secret key */
void
dh_hash_digest(struct dh_state *self)
{
  dh_hash_update(self, ssh_format("%n%n%S",
				  self->e, self->f,
				  self->K));
  self->exchange_hash = hash_digest_string(self->hash);
}

void
init_dh_state(struct dh_state *self,
	      const struct dh_params *params,
	      struct kexinit_state *kex)
{
  mpz_init(self->e);
  mpz_init(self->f);
  mpz_init(self->secret);

  self->K = NULL;
  
  self->params = params;
  self->hash = make_hash(params->H);
  self->exchange_hash = NULL;

  dh_hash_update(self,
		 ssh_format("%S%S%S%S",
			    kex->version[0],
			    kex->version[1],
			    kex->literal_kexinit[0],
			    kex->literal_kexinit[1]));
}

/* R is set to a random, secret, exponent, and V set to is g^r */
void
dh_generate_secret(const struct dh_params *self, mpz_t r, mpz_t v)
{
  mpz_t tmp;

  /* Generate a random number, 1 < x < O(G) = (p-1)/2 */
  mpz_init_set(tmp, self->modulo);  
  mpz_sub_ui(tmp, tmp, 2);
  nettle_mpz_random(r, NULL, lsh_random, tmp);
  mpz_add_ui(r, r, 1);
  mpz_clear(tmp);

  mpz_powm(v, self->generator, r, self->modulo);
}
