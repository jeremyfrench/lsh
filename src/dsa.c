/* dsa.c
 *
 * $Id$
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

#include "publickey_crypto.h"

#include "atoms.h"
#include "bignum.h"
#include "crypto.h"
#include "format.h"
#include "parse.h"
#include "sha.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "dsa.c.x"

#define WITH_DSA_CLASSIC 1

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
     (name dsa_signer_variant)
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
     (name dsa_verifier_variant)
     (super verifier)
     (vars
       (dsa object dsa_verifier)))
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

  debug("DSA hash: %xn\n", h);
  
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

  debug("generic_dsa_sign, k: %xn\n", k);
  
  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_powm(r, closure->public.g, k, closure->public.p);

  debug("do_dsa_sign, group element: %xn\n", r);
  
  mpz_fdiv_r(r, r, closure->public.q);

  debug("do_dsa_sign, r: %xn\n", r);

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

  debug("generic_dsa_sign, s: %xn\n", s);
  
  mpz_clear(k);
  mpz_clear(tmp);
}

static UINT32 dsa_blob_length(mpz_t r, mpz_t s)
{
  UINT32 r_length = bignum_format_u_length(r);
  UINT32 s_length = bignum_format_u_length(s);

  return MAX(r_length, s_length);
}

static void dsa_blob_write(mpz_t r, mpz_t s, UINT32 length, UINT8 *buf)
{
  bignum_write(r, length, buf);
  bignum_write(s, length, buf + length);
}

static struct lsh_string *
do_dsa_sign(struct signer *c,
	    UINT32 msg_length,
	    UINT8 *msg)
{
  CAST(dsa_signer, closure, c);
  mpz_t r, s;
  struct lsh_string *signature;
  UINT32 buf_length;
  UINT8 *p;
  
  mpz_init(r); mpz_init(s);
  generic_dsa_sign(closure, msg_length, msg, r, s);
      
  /* Build signature */
  buf_length = dsa_blob_length(r, s);
  signature = ssh_format("%a%r", ATOM_SSH_DSS, buf_length * 2, &p);
  dsa_blob_write(r, s, buf_length, p);
  
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
static struct lsh_string *do_dsa_sign_kludge(struct signer *c,
					     UINT32 msg_length,
					     UINT8 *msg)
{
  CAST(dsa_signer_variant, self, c);
  mpz_t r, s;
  struct lsh_string *signature;
  UINT32 buf_length;
  UINT8 *p;

  mpz_init(r); mpz_init(s);
  generic_dsa_sign(self->dsa, msg_length, msg, r, s);

  /* Build signature */
  buf_length = dsa_blob_length(r, s);
  /* NOTE: This includes one legth field. Is that right? */
  signature = ssh_format("%r", buf_length * 2, &p);
  dsa_blob_write(r, s, buf_length, p);

  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

struct signer *make_dsa_signer_kludge(struct signer *s)
{
  NEW(dsa_signer_variant, self);
  CAST(dsa_signer, dsa, s);
	
  self->super.sign = do_dsa_sign_kludge;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* DATAFELLOWS_SSH2_SSH_DSA_KLUDGE */

#if WITH_DSA_CLASSIC
/* Uses the (better) format from an obsoleted draft */
static struct lsh_string *
do_dsa_sign_classic(struct signer *c,
		    UINT32 length,
		    UINT8 *msg)
{
  CAST(dsa_signer_variant, self, c);
  mpz_t r, s;
  struct lsh_string *signature;

  mpz_init(r); mpz_init(s);
  generic_dsa_sign(self->dsa, length, msg, r, s);
      
  /* Build signature */

  signature = ssh_format("%a%n%n", ATOM_SSH_DSS, r, s);
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

struct signer *make_dsa_signer_classic(struct signer *s)
{
  NEW(dsa_signer_variant, self);
  CAST(dsa_signer, dsa, s);
	
  self->super.sign = do_dsa_sign_classic;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* WITH_DSA_CLASSIC */


/* Verifying DSA signatures */

/* The caller should make sure that r and s are non-negative.
 * That tyey are less than q is checked here. */
static int generic_dsa_verify(struct dsa_public *key,
			      UINT32 length,
			      UINT8 *msg,
			      mpz_t r, mpz_t s)
{
  mpz_t w, tmp, v;
  int res;
  
  debug("generic_dsa_verify, r: %xn\n"
	"                    s: %xn\n", r, s);

  if ( (mpz_cmp(r, key->q) >= 0)
       || (mpz_cmp(s, key->q) >= 0) )
    return 0;
  
  /* Compute w = s^-1 (mod q) */
  mpz_init(w);

  /* FIXME: mpz_invert generates negative inverses. Is this a problem? */
  if (!mpz_invert(w, s, key->q))
    {
      werror("generic_dsa_verify: s non-invertible.\n");
      mpz_clear(w);
      return 0;
    }

  debug("generic_dsa_verify, w: %xn\n", w);

  /* Compute hash */
  mpz_init(tmp);
  dsa_hash(tmp, length, msg);

  /* g^{w * h (mod q)} (mod p)  */

  mpz_init(v);

  mpz_mul(tmp, tmp, w);
  mpz_fdiv_r(tmp, tmp, key->q);

  debug("u1: %xn\n", tmp);
  
  mpz_powm(v, key->g, tmp, key->p);

  /* y^{w * r (mod q) } (mod p) */
  mpz_mul(tmp, r, w);
  mpz_fdiv_r(tmp, tmp, key->q);

  debug("u2: %xn\n", tmp);

  mpz_powm(tmp, key->y, tmp, key->p);
  
  /* (g^{w * h} * y^{w * r} (mod p) ) (mod q) */
  mpz_mul(v, v, tmp);
  mpz_fdiv_r(v, v, key->p);

  debug("generic_dsa_verify, group element: %xn\n", v);
  
  mpz_fdiv_r(v, v, key->q);

  debug("generic_dsa_verify, v: %xn\n", v);

  res = !mpz_cmp(v, r);

  mpz_clear(w);
  mpz_clear(tmp);
  mpz_clear(v);

  return res;
}

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

  UINT32 buf_length;
  UINT8 *buf;
  
  simple_buffer_init(&buffer, signature_length, signature_data);
  if (!(parse_atom(&buffer, &atom)
	&& (atom == ATOM_SSH_DSS)
	&& parse_string(&buffer, &buf_length, &buf)
	&& !(buf_length % 2)) )
    return 0;

  mpz_init(r);
  mpz_init(s);

  buf_length /= 2;
  
  bignum_parse_u(r, buf_length, buf);
  bignum_parse_u(s, buf_length, buf + buf_length);
    
  res = generic_dsa_verify(&closure->public, length, msg, r, s);
  
  mpz_clear(r);
  mpz_clear(s);

  return res;
}

#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
static int do_dsa_verify_kludge(struct verifier *c,
				UINT32 length,
				UINT8 *msg,
				UINT32 signature_length,
				UINT8 * signature_data)
{
  CAST(dsa_verifier_variant, self, c);
  struct simple_buffer buffer;

  int res;
  
  mpz_t r, s;

  UINT32 buf_length;
  UINT8 *buf;
  
  simple_buffer_init(&buffer, signature_length, signature_data);

  /* NOTE: This includes one legth field. Is that right? */
  if (!(parse_string(&buffer, &buf_length, &buf)
	&& !(buf_length % 2)) )
    return 0;

  mpz_init(r);
  mpz_init(s);

  buf_length /= 2;
  
  bignum_parse_u(r, buf_length, buf);
  bignum_parse_u(s, buf_length, buf + buf_length);
    
  res = generic_dsa_verify(&self->dsa->public, length, msg, r, s);
  
  mpz_clear(r);
  mpz_clear(s);

  return res;
}

struct verifier *make_dsa_verifier_kludge(struct verifier *v)
{
  NEW(dsa_verifier_variant, self);
  CAST(dsa_verifier, dsa, v);
	
  self->super.verify = do_dsa_verify_kludge;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* DATAFELLOWS_SSH2_SSH_DSA_KLUDGE */
     
#if WITH_DSA_CLASSIC
static int do_dsa_verify_classic(struct verifier *c,
				 UINT32 length,
				 UINT8 *msg,
				 UINT32 signature_length,
				 UINT8 * signature_data)
{
  CAST(dsa_verifier_variant, self, c);
  struct simple_buffer buffer;

  int res;
  
  int atom;
  mpz_t r, s;

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
	 && (mpz_sgn(s) == 1) ))
    {
      mpz_clear(r);
      mpz_clear(s);
      return 0;
    }
  
  res = generic_dsa_verify(&self->dsa->public, length, msg, r, s);
  
  mpz_clear(r);
  mpz_clear(s);

  return res;
}

struct verifier *make_dsa_verifier_classic(struct verifier *v)
{
  NEW(dsa_verifier_variant, self);
  CAST(dsa_verifier, dsa, v);
	
  self->super.verify = do_dsa_verify_classic;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* WITH_DSA_CLASSIC */

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

#if 0
static struct lsh_string *dsa_public_key(struct signer *dsa)
{
  return ssh_format("%a%n%n%n%n",
		    ATOM_SSH_DSS, dsa->p, dsa->q, dsa->g, dsa->y);
}
#endif
