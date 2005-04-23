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

#include "publickey_crypto.h"

#include "connection.h"
#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "randomness.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"


const struct dh_params *
make_dh_params(const char *modulo, unsigned generator,
	       const struct hash_algorithm *H)
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
make_dh_group1(const struct hash_algorithm *H)
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
make_dh_group14(const struct hash_algorithm *H)
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

void
dh_hash_update(struct dh_state *self,
	       struct lsh_string *s, int free)
{
  debug("dh_hash_update: %xS\n", s);
  
  hash_update(self->hash, STRING_LD(s));
  if (free)
    lsh_string_free(s);
}

/* Hashes e, f, and the shared secret key */
void
dh_hash_digest(struct dh_state *self)
{
  dh_hash_update(self, ssh_format("%n%n%S",
				  self->e, self->f,
				  self->K), 1);
  self->exchange_hash = hash_digest_string(self->hash);

  debug("dh_hash_digest: %xS\n", self->exchange_hash);  
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

  debug("init_dh_instance\n"
	" V_C: %pS\n", kex->version[0]);
  debug(" V_S: %pS\n", kex->version[1]);
  debug(" I_C: %xS\n", kex->literal_kexinit[0]);
  debug(" I_S: %xS\n", kex->literal_kexinit[1]);

  dh_hash_update(self,
		 ssh_format("%S%S%S%S",
			    kex->version[0],
			    kex->version[1],
			    kex->literal_kexinit[0],
			    kex->literal_kexinit[1]),
		 1);
}

/* R is set to a random, secret, exponent, and V set to is g^r */
void
dh_generate_secret(const struct dh_params *self,
		   struct randomness *random, 
		   mpz_t r, mpz_t v)
{
  mpz_t tmp;

  assert(random->quality == RANDOM_GOOD);
  
  /* Generate a random number, 1 < x < O(G) = (p-1)/2 */
  mpz_init_set(tmp, self->modulo);  
  mpz_sub_ui(tmp, tmp, 2);
  nettle_mpz_random(r, random, lsh_random, tmp);
  mpz_add_ui(r, r, 1);
  mpz_clear(tmp);

  mpz_powm(v, self->generator, r, self->modulo);
}

#if 0
struct lsh_string *
dh_make_client_msg(struct dh_instance *self)
{
  dh_generate_secret(self->method, self->secret, self->e);
  return ssh_format("%c%n", SSH_MSG_KEXDH_INIT, self->e);
}

/* Returns the host key. */
struct lsh_string *
dh_process_server_msg(struct dh_instance *self,
		      struct lsh_string **signature,
		      struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  mpz_t tmp;

  struct lsh_string *key = NULL;
  struct lsh_string *s = NULL;
  
  simple_buffer_init(&buffer, STRING_LD(packet));

  if (! (parse_uint8(&buffer, &msg_number)
	 && (msg_number == SSH_MSG_KEXDH_REPLY)
	 && (key = parse_string_copy(&buffer))
	 /* FIXME: Pass a more restrictive limit to parse_bignum. */
	 && (parse_bignum(&buffer, self->f, 0))
	 && (mpz_cmp_ui(self->f, 1) > 0)
	 && zn_range(self->method->G, self->f)
	 && (s = parse_string_copy(&buffer))
	 && parse_eod(&buffer)))
    {
      lsh_string_free(key);
      lsh_string_free(s);
      return NULL;
    }

  mpz_init(tmp);
  
  zn_exp(self->method->G, tmp, self->f, self->secret);
  self->K = ssh_format("%ln", tmp);

  mpz_clear(tmp);

  dh_hash_update(self, ssh_format("%S", key), 1);
  dh_hash_digest(self);
    
  *signature = s;
  return key;
}

#endif
