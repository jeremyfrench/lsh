/* publickey_crypto.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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

#include "publickey_crypto.h"

#include "atoms.h"
#include "bignum.h"
#include "connection.h"
#include "crypto.h"
#include "format.h"
#include "parse.h"
#include "sha.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "publickey_crypto.h.x"
#undef GABA_DEFINE

/* #include "publickey_crypto.c.x" */

struct keypair *
make_keypair(UINT32 type,
	     struct lsh_string *public,
	     struct signer *private)
{
  NEW(keypair, self);
  
  self->type = type;
  self->public = public;
  self->private = private;
  return self;
}

static int
zn_range(struct abstract_group *c, mpz_t x)
{
  CAST(group_zn, closure, c);

  /* FIXME: As we are really working in a cyclic subgroup, we should
   * also try raising the element to the group order and check that we
   * get 1. Without that test, some numbers in the range [1, modulo-1]
   * will pass as members even if they are not generated by g. */
  return ( (mpz_sgn(x) == 1) && (mpz_cmp(x, closure->modulo) < 0) );
}

#if 0
static int
zn_member(struct abstract_group *c, mpz_t x)
{
  if (zn_range(c, x))
    {
      CAST(group_zn, closure, c);
      mpz_t t;
      int res;
      
      mpz_init(t);

      mpz_powm(t, x, closure->order, closure->modulo);
      res = !mpz_cmp_ui(t, 1);

      mpz_clear(t);

      return res;
    }
  return 0;
}
#endif

static void
zn_invert(struct abstract_group *c, mpz_t res, mpz_t x)
{
  CAST(group_zn, closure, c);

  if (!mpz_invert(res, x, closure->modulo))
    fatal("zn_invert: element is non-invertible\n");

  mpz_fdiv_r(res, res, closure->modulo);
}

static void
zn_combine(struct abstract_group *c, mpz_t res, mpz_t a, mpz_t b)
{
  CAST(group_zn, closure, c);

  mpz_mul(res, a, b);
  mpz_fdiv_r(res, res, closure->modulo);
}

static void
zn_power(struct abstract_group *c, mpz_t res, mpz_t g, mpz_t e)
{
  CAST(group_zn, closure, c);

  mpz_powm(res, g, e, closure->modulo);
}

static void
zn_small_power(struct abstract_group *c, mpz_t res, mpz_t g, UINT32 e)
{
  CAST(group_zn, closure, c);

  mpz_powm_ui(res, g, e, closure->modulo);
}

/* Assumes p is a prime number */
struct group_zn *
make_zn(mpz_t p, mpz_t g, mpz_t order)
{
  NEW(group_zn, res);

  res->super.range = zn_range;
  res->super.invert = zn_invert;
  res->super.combine = zn_combine;
  res->super.power = zn_power;     /* Pretty Mutation! Magical Recall! */
  res->super.small_power = zn_small_power;
  
  mpz_init_set(res->modulo, p);
  mpz_init_set(res->super.generator, g);
  mpz_init_set(res->super.order, order);

  return res;
}

#if 0
/* diffie-hellman */

void
init_diffie_hellman_instance(struct diffie_hellman_method *m,
			     struct diffie_hellman_instance *self,
			     struct ssh_connection *c)
{
  struct lsh_string *s;
  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  mpz_init(self->e);
  mpz_init(self->f);
  mpz_init(self->secret);
  mpz_init(self->K);
  
  self->method = m;
  self->hash = MAKE_HASH(m->H);
  self->exchange_hash = NULL;

  debug("init_diffie_hellman_instance()\n"
	" V_C: %pS\n", c->versions[CONNECTION_CLIENT]);
  debug(" V_S: %pS\n", c->versions[CONNECTION_SERVER]);
  debug(" I_C: %pS\n", c->literal_kexinits[CONNECTION_CLIENT]);
  debug(" I_C: %pS\n", c->literal_kexinits[CONNECTION_SERVER]);

  s = ssh_format("%S%S%S%S",
		 c->versions[CONNECTION_CLIENT],
		 c->versions[CONNECTION_SERVER],
		 c->literal_kexinits[CONNECTION_CLIENT],
		 c->literal_kexinits[CONNECTION_SERVER]);
  HASH_UPDATE(self->hash, s->length, s->data);

  lsh_string_free(s);  

  /* We don't need the kexinit strings anymore. */
  lsh_string_free(c->literal_kexinits[CONNECTION_CLIENT]);
  lsh_string_free(c->literal_kexinits[CONNECTION_SERVER]);
  c->literal_kexinits[CONNECTION_CLIENT] = NULL;
  c->literal_kexinits[CONNECTION_SERVER] = NULL;
}

struct diffie_hellman_method *
make_dh1(struct randomness *r)
{
  NEW(diffie_hellman_method, res);
  mpz_t p;
  mpz_t order;
  
  mpz_init_set_str(p,
		   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		   "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		   "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		   "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		   "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
		   "FFFFFFFFFFFFFFFF", 16);

  mpz_init_set(order, p);
  mpz_sub_ui(order, order, 1);
  mpz_fdiv_q_2exp(order, order, 1);

  res->G = make_zn(p, order);
  mpz_clear(p);
  mpz_clear(order);
  
  mpz_init_set_ui(res->generator, 2);

  res->H = &sha1_algorithm;
  res->random = r;
  
  return res;
}

void
dh_generate_secret(struct diffie_hellman_instance *self,
		   mpz_t r)
{
  mpz_t tmp;

  /* Generate a random number, 1 < x <= p-1 = O(G) */
  mpz_init_set(tmp, self->method->G->order);  
  mpz_sub_ui(tmp, tmp, 1);
  bignum_random(self->secret, self->method->random, tmp);
  mpz_add_ui(self->secret, self->secret, 1);
  mpz_clear(tmp);

  GROUP_POWER(self->method->G, r, self->method->generator, self->secret);
}

struct lsh_string *
dh_make_client_msg(struct diffie_hellman_instance *self)
{
  dh_generate_secret(self, self->e);
  return ssh_format("%c%n", SSH_MSG_KEXDH_INIT, self->e);
}

int
dh_process_client_msg(struct diffie_hellman_instance *self,
		      struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (! (parse_uint8(&buffer, &msg_number)
	 && (msg_number == SSH_MSG_KEXDH_INIT)
	 && parse_bignum(&buffer, self->e)
	 && (mpz_cmp_ui(self->e, 1) > 0)
	 && GROUP_MEMBER(self->method->G, self->e)
	 && parse_eod(&buffer) ))
    return 0;

  GROUP_POWER(self->method->G, self->K, self->e, self->secret);
  return 1;
}

#if 0
void dh_hash_update(struct diffie_hellman_instance *self,
		    struct lsh_string *packet)
{
  debug("dh_hash_update, length = %i, data:\n", packet->length);
  debug_safe(packet->length, packet->data);
  debug("\n");
  
  HASH_UPDATE(self->hash, packet->length, packet->data);
}
#endif

/* Hashes server key, e and f */
void
dh_hash_digest(struct diffie_hellman_instance *self, UINT8 *digest)
{
  struct lsh_string *s = ssh_format("%S%n%n%n",
				    self->server_key,
				    self->e, self->f,
				    self->K);
  debug("dh_hash_digest()\n '%pS'\n", s);
  
  HASH_UPDATE(self->hash, s->length, s->data);
  lsh_string_free(s);

  HASH_DIGEST(self->hash, digest);
}

void
dh_make_server_secret(struct diffie_hellman_instance *self)
{
  dh_generate_secret(self, self->f);
}

struct lsh_string *
dh_make_server_msg(struct diffie_hellman_instance *self,
		   struct signer *s)
{
  self->exchange_hash = lsh_string_alloc(self->hash->hash_size);
  
  dh_hash_digest(self, self->exchange_hash->data);

  return ssh_format("%c%S%n%fS",
		    SSH_MSG_KEXDH_REPLY,
		    self->server_key,
		    self->f, SIGN(s,
				  self->exchange_hash->length,
				  self->exchange_hash->data));
}

int
dh_process_server_msg(struct diffie_hellman_instance *self,
		      struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!(parse_uint8(&buffer, &msg_number)
	&& (msg_number == SSH_MSG_KEXDH_REPLY)
	&& (self->server_key = parse_string_copy(&buffer))
	&& (parse_bignum(&buffer, self->f))
	&& (mpz_cmp_ui(self->f, 1) > 0)
	&& GROUP_MEMBER(self->method->G, self->f)
	&& (self->signature = parse_string_copy(&buffer))
	&& parse_eod(&buffer)))
    return 0;

  GROUP_POWER(self->method->G, self->K, self->f, self->secret);
  return 1;
}
	  
int
dh_verify_server_msg(struct diffie_hellman_instance *self,
		     struct verifier *v)
{
  self->exchange_hash = lsh_string_alloc(self->hash->hash_size);
  
  dh_hash_digest(self, self->exchange_hash->data);

  return VERIFY(v,
		self->hash->hash_size, self->exchange_hash->data,
		self->signature->length, self->signature->data);
}

#endif
