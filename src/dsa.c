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
#include "sexp.h"
#include "sha.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "dsa.c.x"

/* DSA signatures */

/* GABA:
   (class
     (name dsa_signer_variant)
     (super signer)
     (vars
       (dsa object dsa_signer)))
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

static void dsa_hash(mpz_t h, UINT32 length, const UINT8 *msg)
{
  /* Compute hash */
  struct hash_instance *hash = MAKE_HASH(&sha1_algorithm);
  UINT8 *digest = alloca(hash->hash_size);
  HASH_UPDATE(hash, length, msg);
  HASH_DIGEST(hash, digest);

  bignum_parse_u(h, hash->hash_size, digest);

  debug("DSA hash: %xn\n", h);
  
  KILL(hash);
}

static void generic_dsa_sign(struct dsa_signer *closure,
			     UINT32 length, const UINT8 *msg,
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

  debug("generic_dsa_sign, group element: %xn\n", r);
  
  mpz_fdiv_r(r, r, closure->public.q);

  debug("generic_dsa_sign, r: %xn\n", r);

  /* Compute hash */
  dsa_hash(tmp, length, msg);
  
  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, closure->public.q))
    {
      fatal("generic_dsa_sign: k non-invertible\n");
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

static UINT32
dsa_blob_length(mpz_t r, mpz_t s)
{
  UINT32 r_length = bignum_format_u_length(r);
  UINT32 s_length = bignum_format_u_length(s);

  return MAX(r_length, s_length);
}

static void
dsa_blob_write(mpz_t r, mpz_t s, UINT32 length, UINT8 *buf)
{
  bignum_write(r, length, buf);
  bignum_write(s, length, buf + length);
}

static struct lsh_string *
do_dsa_sign(struct signer *c,
	    UINT32 msg_length,
	    const UINT8 *msg)
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
  signature = ssh_format("%i%a%r",
			 /* NOTE: This outer length field is somewhat
			  * redundant, but required by the spec. */
			 get_atom_length(ATOM_SSH_DSS) + buf_length * 2 + 8,
			 ATOM_SSH_DSS, buf_length * 2, &p);
  dsa_blob_write(r, s, buf_length, p);
  
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

static struct sexp *
do_dsa_sign_spki(struct signer *c,
		 struct sexp *hash, struct sexp *principal,
		 UINT32 msg_length,
		 const UINT8 *msg)
{
  CAST(dsa_signer, closure, c);
  mpz_t r, s;
  struct sexp *signature;
    
  mpz_init(r); mpz_init(s);
  generic_dsa_sign(closure, msg_length, msg, r, s);
      
  /* Build signature */
  signature = sexp_l(5, sexp_a(ATOM_SIGNATURE), hash, principal,
		     sexp_l(2, ATOM_R, sexp_un(r), -1),
		     sexp_l(2, ATOM_S, sexp_un(s), -1), -1);
  
  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

static struct sexp *
do_dsa_public_key(struct signer *s)
{
  CAST(dsa_signer, self, s);

  return sexp_l(2, sexp_a(ATOM_PUBLIC_KEY),
		sexp_l(5, sexp_a(ATOM_DSA),
		       sexp_l(2, sexp_a(ATOM_P), sexp_un(self->public.p), -1),
		       sexp_l(2, sexp_a(ATOM_Q), sexp_un(self->public.q), -1),
		       sexp_l(2, sexp_a(ATOM_G), sexp_un(self->public.g), -1),
		       sexp_l(2, sexp_a(ATOM_Y), sexp_un(self->public.y), -1),
		       -1), -1);
}

#if DATAFELLOWS_WORKAROUNDS

static struct lsh_string *
do_dsa_sign_kludge(struct signer *c,
		   UINT32 msg_length,
		   const UINT8 *msg)
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

  /* NOTE: This doesn't include any length field. Is that right? */
  signature = ssh_format("%lr", buf_length * 2, &p);
  dsa_blob_write(r, s, buf_length, p);

  mpz_clear(r);
  mpz_clear(s);

  return signature;
}

struct signer *
make_dsa_signer_kludge(struct signer *s)
{
  NEW(dsa_signer_variant, self);
  CAST(dsa_signer, dsa, s);
	
  self->super.sign = do_dsa_sign_kludge;
  self->super.sign_spki = NULL;
  
  self->dsa = dsa;
  return &self->super;
}

#endif /* DATAFELLOWS_WORKAROUNDS */


/* Verifying DSA signatures */

/* The caller should make sure that r and s are non-negative.
 * That they are less than q is checked here. */
static int
generic_dsa_verify(struct dsa_public *key,
		   UINT32 length,
		   const UINT8 *msg,
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

  /* NOTE: mpz_invert somtimes generates negative inverses. */
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

static int
do_dsa_verify(struct verifier *c,
	      UINT32 length,
	      const UINT8 *msg,
	      UINT32 signature_length,
	      const UINT8 *signature_data)
{
  CAST(dsa_verifier, closure, c);
  struct simple_buffer buffer;

  int res;
  
  int atom;
  mpz_t r, s;

  /* NOTE: The outer length field is somewhat redundant, but required
   * by the spec. */
  UINT32 outer_length;

  UINT32 buf_length;
  const UINT8 *buf;
  
  simple_buffer_init(&buffer, signature_length, signature_data);
  if (!(parse_uint32(&buffer, &outer_length)
	&& (outer_length == signature_length - 4)
	&& parse_atom(&buffer, &atom)
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

static int
do_dsa_verify_spki(struct verifier *c,
		   UINT32 length,
		   const UINT8 *msg,
		   struct sexp_iterator *i)
{
  CAST(dsa_verifier, closure, c);

  int res;
  mpz_t r, s;

  mpz_init(r);
  mpz_init(s);

  /* NOTE: With the current definition of sexp_get_un, there are no
   * requirements on the order in which r and s occur. */
  res = (SEXP_LEFT(i) == 2)
    && sexp_get_un(i, ATOM_R, r)
    && sexp_get_un(i, ATOM_S, s)
    && generic_dsa_verify(&closure->public, length, msg, r, s);

  mpz_clear(r);
  mpz_clear(s);

  return res;
}

#if DATAFELLOWS_WORKAROUNDS

static int
do_dsa_verify_kludge(struct verifier *c,
		     UINT32 length,
		     const UINT8 *msg,
		     UINT32 signature_length,
		     const UINT8 *signature_data)
{
  CAST(dsa_verifier_variant, self, c);

  int res;
  
  mpz_t r, s;

  UINT32 buf_length;

  /* NOTE: This doesn't include any length field. Is that right? */

  if (signature_length % 2)
    return 0;

  buf_length = signature_length / 2;

  mpz_init(r);
  mpz_init(s);

  bignum_parse_u(r, buf_length, signature_data);
  bignum_parse_u(s, buf_length, signature_data + buf_length);
    
  res = generic_dsa_verify(&self->dsa->public, length, msg, r, s);
  
  mpz_clear(r);
  mpz_clear(s);

  return res;
}

struct verifier *
make_dsa_verifier_kludge(struct verifier *v)
{
  NEW(dsa_verifier_variant, self);
  CAST(dsa_verifier, dsa, v);
	
  self->super.verify = do_dsa_verify_kludge;
  
  self->dsa = dsa;
  return &self->super;
}
#endif /* DATAFELLOWS_WORKAROUNDS */
     

/* FIXME: The allocator could do this kind of initialization
 * automatically. */
void init_dsa_public(struct dsa_public *public)
{
  mpz_init(public->p);
  mpz_init(public->q);
  mpz_init(public->g);
  mpz_init(public->y);
}

static int
spki_init_dsa_public(struct dsa_public *key,
		     struct sexp_iterator *i)
{
  return (sexp_get_un(i, ATOM_P, key->p)
	  && sexp_get_un(i, ATOM_Q, key->q)
	  && sexp_get_un(i, ATOM_G, key->g)
	  && sexp_get_un(i, ATOM_Y, key->y) );
}

static struct signer *
make_dsa_signer(struct signature_algorithm *c,
		struct sexp_iterator *i)
{
  CAST(dsa_algorithm, closure, c);
  NEW(dsa_signer, res);
  init_dsa_public(&res->public);
  mpz_init(res->a);

#if 0
  debug("make_dsa_signer: SEXP_LEFT(i) == %i\n");
  debug("make_dsa_signer: SEXP_GET(i) == %fS\n",
	sexp_format(SEXP_GET(i), SEXP_ADVANCED, 0));
#endif
  
  if ( (SEXP_LEFT(i) == 5)
       && spki_init_dsa_public(&res->public, i)
       && sexp_get_un(i, ATOM_X, res->a) )
    {
      res->random = closure->random;
      res->super.sign = do_dsa_sign;
      res->super.sign_spki = do_dsa_sign_spki;
      res->super.public_key = do_dsa_public_key;
      
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

static struct verifier *
make_dsa_verifier(struct signature_algorithm *self UNUSED,
		  struct sexp_iterator *i)
{
  NEW(dsa_verifier, res);
  init_dsa_public(&res->public);

  if ( (SEXP_LEFT(i) == 4)
       && spki_init_dsa_public(&res->public, i))
    {
      res->super.verify = do_dsa_verify;
      res->super.verify_spki = do_dsa_verify_spki;
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}
  
struct signature_algorithm *make_dsa_algorithm(struct randomness *random)
{
  NEW(dsa_algorithm, dsa);

  dsa->super.make_signer = make_dsa_signer;
  dsa->super.make_verifier = make_dsa_verifier;
  dsa->random = random;

  return &dsa->super;
}


/* Constructor using a key of type ssh-dss */
int parse_dsa_public(struct simple_buffer *buffer,
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

struct dsa_verifier *
make_ssh_dss_verifier(UINT32 public_length,
		      const UINT8 *public)
{
  NEW(dsa_verifier, res);
  struct simple_buffer buffer;
  int atom;

  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  init_dsa_public(&res->public);
  
  simple_buffer_init(&buffer, public_length, public);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    {
      KILL(res);
      return 0;
    }
  
  if (!parse_dsa_public(&buffer, &res->public))
    {
      /* FIXME: Perhaps do some more sanity checks? */
      KILL(res);
      return NULL;
    }

  res->super.verify = do_dsa_verify;
  res->super.verify_spki = do_dsa_verify_spki;
  
  return res;
}

struct lsh_string *
ssh_dss_public_key(struct signer *s)
{
  CAST(dsa_signer, dsa, s);
  return ssh_format("%a%n%n%n%n",
		    ATOM_SSH_DSS,
		    dsa->public.p, dsa->public.q,
		    dsa->public.g, dsa->public.y);
}
