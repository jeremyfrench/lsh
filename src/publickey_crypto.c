/* publickey_crypto.c
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

#include "publickey_crypto.h"

#include "atoms.h"
#include "bignum.h"
#include "crypto.h"
#include "format.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "sha.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "publickey_crypto.h.x"
#undef GABA_DEFINE

#include "publickey_crypto.c.x"

/* DSA signatures */
/* GABA:
   (class
     (name dsa_signer)
     (super signer)
     (vars
       (random object randomness)
       (public struct dsa_public)
       (a bignum)))
*/

/* GABA:
   (class
     (name dsa_signer_kludge)
     (super signer)
     (vars
       (dsa object dsa_signer)))
*/

/* GABA:
   (class
     (name dsa_verifier)
     (super verifier)
     (vars
       (public struct dsa_public)))
*/

/* GABA:
   (class
     (name dsa_algorithm)
     (super signature_algorithm)
     (vars
       (random object randomness)))
*/

static void dsa_hash(mpz_t h, UINT32 length, UINT8 *msg)
{
  /* Compute hash */
  struct hash_instance *hash = MAKE_HASH(&sha_algorithm);
  UINT8 *digest = alloca(hash->hash_size);
  HASH_UPDATE(hash, length, msg);
  HASH_DIGEST(hash, digest);

  bignum_parse_u(h, hash->hash_size, digest);

  debug("DSA hash: %hn\n", h);
  
  KILL(hash);
}

static void generic_dsa_sign(struct dsa_signer *closure,
			     UINT32 length, UINT8 *msg,
			     mpz_t r, mpz_t s)
{
  mpz_t k, tmp;

  assert(r && s);
  
  /* Select k, 0<k<q, randomly */
  mpz_init_set(tmp, closure->public.q);
  mpz_sub_ui(tmp, tmp, 1);

  mpz_init(k);
  bignum_random(k, closure->random, tmp);
  mpz_add_ui(k, k, 1);

  debug("generic_dsa_sign, k: %hn\n", k);
  
  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_powm(r, closure->public.g, k, closure->public.p);

  debug("do_dsa_sign, group element: %hn\n", r);
  
  mpz_fdiv_r(r, r, closure->public.q);

  debug("do_dsa_sign, r: %hn\n", r);

  /* Compute hash */
  dsa_hash(tmp, length, msg);
  
  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, closure->public.q))
    {
      fatal("do_dsa_sign: k non-invertible\n");
    }

  /* Compute signature s = k^-1(h + ar) (mod q) */
  mpz_mul(s, r, closure->a);
  mpz_fdiv_r(s, s, closure->public.q);
  mpz_add(s, s, tmp);
  mpz_mul(s, s, k);
  mpz_fdiv_r(s, s, closure->public.q);

  debug("generic_dsa_sign, s: %hn\n", s);
  
  mpz_clear(k);
  mpz_clear(tmp);
}

static struct lsh_string *do_dsa_sign(struct signer *c,
				      UINT32 length,
				      UINT8 *msg)
{
  CAST(dsa_signer, closure, c);
  mpz_t r, s;
  struct lsh_string *signature;

  mpz_init(r); mpz_init(s);
  generic_dsa_sign(closure, length, msg, r, s);
      
  /* Build signature */
  /* FIXME: Uses the (better) format from an obsoleted draft */
  signature = ssh_format("%a%n%n", ATOM_SSH_DSS, r, s);
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
static struct lsh_string *do_dsa_sign_kludge(struct signer *c,
					     UINT32 length,
					     UINT8 *msg)
{
  CAST(dsa_signer_kludge, self, c);
  mpz_t r, s;
  struct lsh_string *signature;

  mpz_init(r); mpz_init(s);
  generic_dsa_sign(self->dsa, length, msg, r, s);

  /* Build signature */
  /* FIXME: This generates length fields, and it also doesn't
   * guarantee that r and s occupy half of the signature each. */
  signature = ssh_format("%un%un", r, s);
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}
#endif /* DATAFELLOWS_SSH2_SSH_DSA_KLUDGE */


#if 0
static struct lsh_string *dsa_public_key(struct signer *dsa)
{
  return ssh_format("%a%n%n%n%n",
		    ATOM_SSH_DSS, dsa->p, dsa->q, dsa->g, dsa->y);
}
#endif

static int do_dsa_verify(struct verifier *c,
			 UINT32 length,
			 UINT8 *msg,
			 UINT32 signature_length,
			 UINT8 * signature_data)
{
  CAST(dsa_verifier, closure, c);
  struct simple_buffer buffer;

  int res;
  
  int atom;
  mpz_t r, s;

  mpz_t w, tmp, v;

  simple_buffer_init(&buffer, signature_length, signature_data);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    return 0;

  mpz_init(r);
  mpz_init(s);
  if (! (parse_bignum(&buffer, r)
	 && parse_bignum(&buffer, s)
	 && parse_eod(&buffer)
	 && (mpz_sgn(r) == 1)
	 && (mpz_sgn(s) == 1)
	 && (mpz_cmp(r, closure->public.q) < 0)
	 && (mpz_cmp(s, closure->public.q) < 0) ))
    {
      mpz_clear(r);
      mpz_clear(s);
      return 0;
    }
  
  debug("do_dsa_verify, r: %hn\n"
	"               s: %hn\n", r, s);
  
  /* Compute w = s^-1 (mod q) */
  mpz_init(w);

  /* FIXME: mpz_invert generates negative inverses. Is this a problem? */
  if (!mpz_invert(w, s, closure->public.q))
    {
      werror("do_dsa_verify: s non-invertible.\n");
      mpz_clear(r);
      mpz_clear(s);
      mpz_clear(w);
      return 0;
    }

  debug("do_dsa_verify, w: %hn\n", w);

  /* Compute hash */
  mpz_init(tmp);
  dsa_hash(tmp, length, msg);

  /* g^{w * h (mod q)} (mod p)  */

  mpz_init(v);

  mpz_mul(tmp, tmp, w);
  mpz_fdiv_r(tmp, tmp, closure->public.q);

  debug("u1: %hn\n", tmp);
  
  mpz_powm(v, closure->public.g, tmp, closure->public.p);

  /* y^{w * r (mod q) } (mod p) */
  mpz_mul(tmp, r, w);
  mpz_fdiv_r(tmp, tmp, closure->public.q);

  debug("u2: %hn\n", tmp);

  mpz_powm(tmp, closure->public.y, tmp, closure->public.p);
  
  /* (g^{w * h} * y^{w * r} (mod p) ) (mod q) */
  mpz_mul(v, v, tmp);
  mpz_fdiv_r(v, v, closure->public.p);

  debug("do_dsa_verify, group element: %hn\n", v);
  
  mpz_fdiv_r(v, v, closure->public.q);

  debug("do_dsa_verify, v: %hn\n", v);

  res = mpz_cmp(v, r);

  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(w);
  mpz_clear(tmp);
  mpz_clear(v);

  return !res;
}

static int parse_dsa_public(struct simple_buffer *buffer,
			    struct dsa_public *public)
{
  return (parse_bignum(buffer, public->p)
	  && (mpz_sgn(public->p) == 1)
	  && parse_bignum(buffer, public->q)
	  && (mpz_sgn(public->q) == 1)
	  && (mpz_cmp(public->q, public->p) < 0) /* q < p */ 
	  && parse_bignum(buffer, public->g)
	  && (mpz_sgn(public->g) == 1)
	  && (mpz_cmp(public->g, public->p) < 0) /* g < p */ 
	  && parse_bignum(buffer, public->y) 
	  && (mpz_sgn(public->y) == 1)
	  && (mpz_cmp(public->y, public->p) < 0) /* y < p */  );
}

/* FIXME: Outside of the protocol transactions, keys should be stored
 * in SPKI-style S-expressions. */
static struct signer *make_dsa_signer(struct signature_algorithm *c,
				      UINT32 public_length,
				      UINT8 *public,
				      UINT32 private_length,
				      UINT8 *private)
{
  CAST(dsa_algorithm, closure, c);
  NEW(dsa_signer, res);
  
  struct simple_buffer public_buffer;
  struct simple_buffer private_buffer;  
  int atom;

  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  mpz_init(res->public.p);
  mpz_init(res->public.q);
  mpz_init(res->public.g);
  mpz_init(res->public.y);
  mpz_init(res->a);
  
  simple_buffer_init(&public_buffer, public_length, public);
  if (!parse_atom(&public_buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    {
      KILL(res);
      return 0;
    }
  simple_buffer_init(&private_buffer, private_length, private);

  if (! (parse_dsa_public(&public_buffer, &res->public)
  	 && parse_bignum(&private_buffer, res->a)
	 /* FIXME: Perhaps do some more sanity checks? */
	 && (mpz_sgn(res->a) == 1)
	 && parse_eod(&private_buffer) ))
    {
      KILL(res);
      return NULL;
    }
  
  res->super.sign = do_dsa_sign;
  res->random = closure->random;

  return &res->super;
}

#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
struct signer *make_dsa_signer_kludge(struct signer *s)
{
  NEW(dsa_signer_kludge, self);
  CAST(dsa_signer, dsa, s);
	
  self->super.sign = do_dsa_sign_kludge;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* DATAFELLOWS_SSH2_SSH_DSA_KLUDGE */

static struct verifier *
make_dsa_verifier(struct signature_algorithm *closure UNUSED,
		  UINT32 public_length,
		  UINT8 *public)
{
  NEW(dsa_verifier, res);
  struct simple_buffer buffer;
  int atom;

  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  mpz_init(res->public.p);
  mpz_init(res->public.q);
  mpz_init(res->public.g);
  mpz_init(res->public.y);
  
  simple_buffer_init(&buffer, public_length, public);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    {
      KILL(res);
      return 0;
    }
  
  if (!parse_dsa_public(&buffer, &res->public))
    /* FIXME: Perhaps do some more sanity checks? */
    {
      KILL(res);
      return NULL;
    }

  res->super.verify = do_dsa_verify;
  return &res->super;
}

struct signature_algorithm *make_dsa_algorithm(struct randomness *random)
{
  NEW(dsa_algorithm, dsa);

  dsa->super.make_signer = make_dsa_signer;
  dsa->super.make_verifier = make_dsa_verifier;
  dsa->random = random;

  return &dsa->super;
}
    
/* Groups */
/* GABA:
   (class
     (name group_zn)
     (super group)
     (vars
       (modulo bignum)))
*/

static int zn_member(struct group *c, mpz_t x)
{
  CAST(group_zn, closure, c);

  /* FIXME: As we are really working in a cyclic subgroup, we should
   * also try raising the element to the group order and check that we
   * get 1. Without that test, some numbers in the range [1, modulo-1]
   * will pass as members even if they are not generated by g. */
  return ( (mpz_sgn(x) == 1) && (mpz_cmp(x, closure->modulo) < 0) );
}

static void zn_invert(struct group *c, mpz_t res, mpz_t x)
{
  CAST(group_zn, closure, c);

  if (!mpz_invert(res, x, closure->modulo))
    fatal("zn_invert: element is non-invertible\n");

  mpz_fdiv_r(res, res, closure->modulo);
}

static void zn_combine(struct group *c, mpz_t res, mpz_t a, mpz_t b)
{
  CAST(group_zn, closure, c);

  mpz_mul(res, a, b);
  mpz_fdiv_r(res, res, closure->modulo);
}

static void zn_power(struct group *c, mpz_t res, mpz_t g, mpz_t e)
{
  CAST(group_zn, closure, c);

  mpz_powm(res, g, e, closure->modulo);
}

/* Assumes p is a prime number */
struct group *make_zn(mpz_t p, mpz_t order)
{
  NEW(group_zn, res);

  res->super.member = zn_member;
  res->super.invert = zn_invert;
  res->super.combine = zn_combine;
  res->super.power = zn_power;     /* Pretty Mutation! Magical Recall! */
  
  mpz_init_set(res->modulo, p);
  mpz_init_set(res->super.order, order);

  return &res->super;
}

/* diffie-hellman */

void init_diffie_hellman_instance(struct diffie_hellman_method *m,
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

struct diffie_hellman_method *make_dh1(struct randomness *r)
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

  res->H = &sha_algorithm;
  res->random = r;
  
  return res;
}

void dh_generate_secret(struct diffie_hellman_instance *self,
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

struct lsh_string *dh_make_client_msg(struct diffie_hellman_instance *self)
{
  dh_generate_secret(self, self->e);
  return ssh_format("%c%n", SSH_MSG_KEXDH_INIT, self->e);
}

int dh_process_client_msg(struct diffie_hellman_instance *self,
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
void dh_hash_digest(struct diffie_hellman_instance *self, UINT8 *digest)
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

void dh_make_server_secret(struct diffie_hellman_instance *self)
{
  dh_generate_secret(self, self->f);
}

struct lsh_string *dh_make_server_msg(struct diffie_hellman_instance *self,
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

int dh_process_server_msg(struct diffie_hellman_instance *self,
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
	  
int dh_verify_server_msg(struct diffie_hellman_instance *self,
			 struct verifier *v)
{
  self->exchange_hash = lsh_string_alloc(self->hash->hash_size);
  
  dh_hash_digest(self, self->exchange_hash->data);

  return VERIFY(v,
		self->hash->hash_size, self->exchange_hash->data,
		self->signature->length, self->signature->data);
}

