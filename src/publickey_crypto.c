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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

#define CLASS_DEFINE
#include "publickey_crypto.h.x"
#undef CLASS_DEFINE

#include "publickey_crypto.c.x"

/* DSS signatures */
/* CLASS:
   (class
     (name dss_signer)
     (super signer)
     (vars
       (random object randomness)
       (public struct dss_public)
       (a bignum)))
*/

/* CLASS:
   (class
     (name dss_verifier)
     (super verifier)
     (vars
       (public struct dss_public)))
*/

/* CLASS:
   (class
     (name dss_algorithm)
     (super signature_algorithm)
     (vars
       (random object randomness)))
*/

static void dss_hash(mpz_t h, UINT32 length, UINT8 *msg)
{
  /* Compute hash */
  struct hash_instance *hash = MAKE_HASH(&sha_algorithm);
  UINT8 *digest = alloca(hash->hash_size);
  HASH_UPDATE(hash, length, msg);
  HASH_DIGEST(hash, digest);

  bignum_parse_u(h, hash->hash_size, digest);

  debug("DSS hash: ");
  debug_mpz(h);
  debug("\n");
  
  KILL(hash);
}

static struct lsh_string *do_dss_sign(struct signer *c,
				      UINT32 length,
				      UINT8 *msg)
{
  CAST(dss_signer, closure, c);
  mpz_t k, r, s, tmp;
  struct lsh_string *signature;

  /* Select k, 0<k<q, randomly */
  mpz_init_set(tmp, closure->public.q);
  mpz_sub_ui(tmp, tmp, 1);

  mpz_init(k);
  bignum_random(k, closure->random, tmp);
  mpz_add_ui(k, k, 1);

  debug("do_dss_sign, k: ");
  debug_mpz(k);
  debug("\n");
  
  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_init(r);
  mpz_powm(r, closure->public.g, k, closure->public.p);

  debug("do_dss_sign, group element: ");
  debug_mpz(r);
  debug("\n");
  
  mpz_fdiv_r(r, r, closure->public.q);

  debug("do_dss_sign, r: ");
  debug_mpz(r);
  debug("\n");

  /* Compute hash */
  dss_hash(tmp, length, msg);
  
  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, closure->public.q))
    {
      werror("do_dss_sign: k non-invertible\n");
      mpz_clear(tmp);
      mpz_clear(k);
      mpz_clear(r);
      return NULL;
    }

  /* Compute signature s = k^-1(h + ar) (mod q) */
  mpz_init(s);
  mpz_mul(s, r, closure->a);
  mpz_fdiv_r(s, s, closure->public.q);
  mpz_add(s, s, tmp);
  mpz_mul(s, s, k);
  mpz_fdiv_r(s, s, closure->public.q);

  debug("do_dss_sign, s: ");
  debug_mpz(s);
  debug("\n");
  
  /* Build signature */
  signature = ssh_format("%a%n%n", ATOM_SSH_DSS, r, s);

  mpz_clear(k);
  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(tmp);

  return signature;
}

#if 0
static struct lsh_string *dss_public_key(struct signer *dss)
{
  return ssh_format("%a%n%n%n%n",
		    ATOM_SSH_DSS, dss->p, dss->q, dss->g, dss->y);
}
#endif

static int do_dss_verify(struct verifier *c,
			 UINT32 length,
			 UINT8 *msg,
			 UINT32 signature_length,
			 UINT8 * signature_data)
{
  CAST(dss_verifier, closure, c);
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
  
  debug("do_dss_verify, r: ");
  debug_mpz(r);
  debug("\n");
  
  debug("do_dss_verify, s: ");
  debug_mpz(s);
  debug("\n");

  /* Compute w = s^-1 (mod q) */
  mpz_init(w);

  /* FIXME: mpz_invert generates negative inverses. Is this a problem? */
  if (!mpz_invert(w, s, closure->public.q))
    {
      werror("do_dss_verify: s non-invertible.\n");
      mpz_clear(r);
      mpz_clear(s);
      mpz_clear(w);
      return 0;
    }

  debug("do_dss_verify, w: ");
  debug_mpz(w);
  debug("\n");

  /* Compute hash */
  mpz_init(tmp);
  dss_hash(tmp, length, msg);

  /* g^{w * h (mod q)} (mod p)  */

  mpz_init(v);

  mpz_mul(tmp, tmp, w);
  mpz_fdiv_r(tmp, tmp, closure->public.q);

  debug("u1: ");
  debug_mpz(tmp);
  debug("\n");
  
  mpz_powm(v, closure->public.g, tmp, closure->public.p);

  /* y^{w * r (mod q) } (mod p) */
  mpz_mul(tmp, r, w);
  mpz_fdiv_r(tmp, tmp, closure->public.q);

  debug("u2: ");
  debug_mpz(tmp);
  debug("\n");

  mpz_powm(tmp, closure->public.y, tmp, closure->public.p);
  
  /* (g^{w * h} * y^{w * r} (mod p) ) (mod q) */
  mpz_mul(v, v, tmp);
  mpz_fdiv_r(v, v, closure->public.p);

  debug("do_dss_verify, group element: ");
  debug_mpz(v);
  debug("\n");
  
  mpz_fdiv_r(v, v, closure->public.q);

  debug("do_dss_verify, v: ");
  debug_mpz(v);
  debug("\n");

  res = mpz_cmp(v, r);

  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(w);
  mpz_clear(tmp);
  mpz_clear(v);

  return !res;
}

static int parse_dss_public(struct simple_buffer *buffer,
			    struct dss_public *public)
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
static struct signer *make_dss_signer(struct signature_algorithm *c,
				      UINT32 public_length,
				      UINT8 *public,
				      UINT32 private_length,
				      UINT8 *private)
{
  CAST(dss_algorithm, closure, c);
  NEW(dss_signer, res);
  
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

  if (! (parse_dss_public(&public_buffer, &res->public)
  	 && parse_bignum(&private_buffer, res->a)
	 /* FIXME: Perhaps do some more sanity checks? */
	 && (mpz_sgn(res->a) == 1)
	 && parse_eod(&private_buffer) ))
    {
      KILL(res);
      return NULL;
    }
  
  res->super.sign = do_dss_sign;
  res->random = closure->random;

  return &res->super;
}

static struct verifier *make_dss_verifier(struct signature_algorithm *closure,
					  UINT32 public_length,
					  UINT8 *public)
{
  NEW(dss_verifier, res);
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
  
  if (!parse_dss_public(&buffer, &res->public))
    /* FIXME: Perhaps do some more sanity checks? */
    {
      KILL(res);
      return NULL;
    }

  res->super.verify = do_dss_verify;
  return &res->super;
}

struct signature_algorithm *make_dss_algorithm(struct randomness *random)
{
  NEW(dss_algorithm, dss);

  dss->super.make_signer = make_dss_signer;
  dss->super.make_verifier = make_dss_verifier;
  dss->random = random;

  return &dss->super;
}
    
/* Groups */
/* CLASS:
   (class
     (name group_zn)
     (super group)
     (vars
       (modulo bignum)))
*/

static int zn_member(struct group *c, mpz_t x)
{
  CAST(group_zn, closure, c);

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
struct group *make_zn(mpz_t p)
{
  NEW(group_zn, res);

  res->super.member = zn_member;
  res->super.invert = zn_invert;
  res->super.combine = zn_combine;
  res->super.power = zn_power;     /* Pretty Mutation! Magical Recall! */
  
  mpz_init_set(res->modulo, p);
  mpz_init_set(res->super.order, p);
  mpz_sub_ui(res->super.order, res->super.order, 1);
  return &res->super;
}

/* diffie-hellman */

void init_diffie_hellman_instance(struct diffie_hellman_method *m,
				  struct diffie_hellman_instance *self,
				  struct ssh_connection *c)
{
  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  mpz_init(self->e);
  mpz_init(self->f);
  mpz_init(self->secret);
  mpz_init(self->K);
  
  self->method = m;
  self->hash = MAKE_HASH(m->H);
  self->exchange_hash = NULL;

  debug("init_diffie_hellman_instance()\n V_C: ");

  debug_safe(c->client_version->length,
	     c->client_version->data);
  HASH_UPDATE(self->hash,
	      c->client_version->length,
	      c->client_version->data);
  debug("\n V_S: ");
  debug_safe(c->server_version->length,
	     c->server_version->data);
  HASH_UPDATE(self->hash,
	      c->server_version->length,
	      c->server_version->data);
  debug("\n I_C: ");
  debug_safe(c->literal_kexinits[CONNECTION_CLIENT]->length,
	     c->literal_kexinits[CONNECTION_CLIENT]->data);
  HASH_UPDATE(self->hash,
	      c->literal_kexinits[CONNECTION_CLIENT]->length,
	      c->literal_kexinits[CONNECTION_CLIENT]->data);
  debug("\n I_C: ");
  debug_safe(c->literal_kexinits[CONNECTION_SERVER]->length,
	     c->literal_kexinits[CONNECTION_SERVER]->data);
  HASH_UPDATE(self->hash,
	      c->literal_kexinits[CONNECTION_SERVER]->length,
	      c->literal_kexinits[CONNECTION_SERVER]->data);
  debug("\n");
  
  lsh_string_free(c->literal_kexinits[CONNECTION_CLIENT]);
  lsh_string_free(c->literal_kexinits[CONNECTION_SERVER]);

  c->literal_kexinits[CONNECTION_SERVER] = NULL;
  c->literal_kexinits[CONNECTION_CLIENT] = NULL;
}

struct diffie_hellman_method *make_dh1(struct randomness *r)
{
  NEW(diffie_hellman_method, res);
  mpz_t p;
  
  mpz_init_set_str(p,
		   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		   "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		   "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		   "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		   "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
		   "FFFFFFFFFFFFFFFF", 16);

  res->G = make_zn(p);
  mpz_clear(p);

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
  int msg_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (! (parse_uint8(&buffer, &msg_number)
	 && (msg_number == SSH_MSG_KEXDH_INIT)
	 && parse_bignum(&buffer, self->e)
	 && (mpz_cmp_ui(self->e, 1) > 0)
	 && (mpz_cmp(self->e, self->method->G->order) <= 0)
	 && parse_eod(&buffer) ))
    return 0;

  GROUP_POWER(self->method->G, self->K, self->e, self->secret);
  return 1;
}

#if 0
void dh_hash_update(struct diffie_hellman_instance *self,
		    struct lsh_string *packet)
{
  debug("dh_hash_update, length = %d, data:\n", packet->length);
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
  debug("dh_hash_digest()\n '");
  debug_safe(s->length,
	     s->data);
  debug("'\n");
  
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
  int msg_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!(parse_uint8(&buffer, &msg_number)
	&& (msg_number == SSH_MSG_KEXDH_REPLY)
	&& (self->server_key = parse_string_copy(&buffer))
	&& (parse_bignum(&buffer, self->f))
	&& (mpz_cmp_ui(self->f, 1) > 0)
	&& (mpz_cmp(self->f, self->method->G->order) <= 0)
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

