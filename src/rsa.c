/* rsa.c
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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
#include "format.h"
#include "parse.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/rsa.h"
#include "nettle/sha.h"

#include <assert.h>
#include <string.h>

#include "rsa.c.x"

#define SA(x) sexp_a(ATOM_##x)

/* We don't allow keys larger than 5000 bits (i.e. 625 octets). Note
 * that allowing really large keys opens for Denial-of-service
 * attacks. */

#define RSA_MAX_SIZE 625

/* GABA:
   (class
     (name rsa_verifier)
     (super verifier)
     (vars
       (key indirect-special "struct rsa_public_key"
            #f rsa_clear_public_key)))
*/

/* GABA:
   (class
     (name rsa_signer)
     (super signer)
     (vars
       (verifier object rsa_verifier)
       (key indirect-special "struct rsa_private_key"
            #f rsa_clear_private_key)))
*/


/* FIXME: Add hash algorithm to signature value? */
static struct sexp *
encode_rsa_sig_val(mpz_t s)
{
  return sexp_un(s);
}

static int
decode_rsa_sig_val(struct sexp *e, mpz_t s, unsigned limit)
{
  return sexp2bignum_u(e, s, limit);
}

static int
spki_init_rsa_verifier(struct rsa_public_key *key,
		       struct sexp_iterator *i)
{
  return (sexp_get_un(i, ATOM_N, key->n, RSA_MAX_SIZE)
	  && sexp_get_un(i, ATOM_E, key->e, RSA_MAX_SIZE)
	  && rsa_prepare_public_key(key));
}


/* NOTE: For now, always use sha1. */
static int
do_rsa_verify(struct verifier *v,
	      int algorithm,
	      UINT32 length,
	      const UINT8 *msg,
	      UINT32 signature_length,
	      const UINT8 *signature_data)
{
  CAST(rsa_verifier, self, v);
  struct sha1_ctx hash;
  
  mpz_t s;
  int res = 0;

  trace("do_rsa_verify: Verifying %a signature\n", algorithm);
  
  mpz_init(s);
  
  switch(algorithm)
    {
    case ATOM_SSH_RSA:
      {
	struct simple_buffer buffer;
	UINT32 length;
	const UINT8 *digits;
	int atom;
	
	simple_buffer_init(&buffer, signature_length, signature_data);

	if (!(parse_atom(&buffer, &atom)
	      && (atom == ATOM_SSH_RSA)
	      && parse_string(&buffer, &length, &digits)
	      && (length <= self->key.size)
	      && parse_eod(&buffer) ))
	  goto fail;

	bignum_parse_u(s, length, digits);

	break;
      }
      
      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:
      {
	struct simple_buffer buffer;
	struct sexp *e;
	
	simple_buffer_init(&buffer, signature_length, signature_data);

	if (! ( (e = sexp_parse_canonical(&buffer))
		&& parse_eod(&buffer)
		&& decode_rsa_sig_val(e, s, self->key.size)) )
	  goto fail;

	break;
      }
      
    default:
      fatal("do_rsa_verify: Internal error!\n");
    }

  sha1_init(&hash);
  sha1_update(&hash, length, msg);
  res = rsa_sha1_verify(&self->key, &hash, s);

 fail:
  mpz_clear(s);
  
  return res;
}

/* FIXME: Add hash algorithm to signature value? */
static int
do_rsa_verify_spki(struct verifier *v,
		   UINT32 length,
		   const UINT8 *msg,
		   struct sexp *e)
{
  CAST(rsa_verifier, self, v);
  struct sha1_ctx hash;
  
  mpz_t s;
  int res;
  
  mpz_init(s);

  sha1_init(&hash);
  sha1_update(&hash, length, msg);
  
  res = (decode_rsa_sig_val(e, s, self->key.size)
	 && rsa_sha1_verify(&self->key, &hash, s));
  
  mpz_clear(s);

  return res;
}

static struct lsh_string *
do_rsa_public_key(struct verifier *s)
{
  CAST(rsa_verifier, self, s);

  return ssh_format("%a%n%n", ATOM_SSH_RSA,
		     self->key.e, self->key.n);
}

static struct sexp *
do_rsa_public_spki_key(struct verifier *s)
{
  CAST(rsa_verifier, self, s);
#if 0
  return sexp_l(3, sexp_a(self->params->name),
		sexp_l(2, SA(N), sexp_un(self->n), -1),
		sexp_l(2, SA(E), sexp_un(self->e), -1),
		-1);
#endif
  /* NOTE: The algorithm name "rsa-pkcs1-sha1" is the SPKI standard,
   * and what lsh-1.2 used. "rsa-pkcs1" makes more sense, and is what
   * gnupg uses internally (I think), and was used by some late
   * lsh-1.3.x versions.
   *
   * However, since it doesn't matter much, for now we follow the SPKI
   * standard and stay compatible with lsh-1.2. */
  return sexp_l(3, sexp_a(ATOM_RSA_PKCS1_SHA1),
		sexp_l(2, SA(N), sexp_un(self->key.n), -1),
		sexp_l(2, SA(E), sexp_un(self->key.e), -1),
		-1);
}


/* NOTE: To initialize an rsa verifier, one must
 *
 * 1. Call this function.
 * 2. Initialize the modulo n and exponent e.
 * 3. Call rsa_prepare_public_key.
 */
static void
init_rsa_verifier(struct rsa_verifier *self)
{
  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  rsa_init_public_key(&self->key);
  
  self->super.verify = do_rsa_verify;
  self->super.verify_spki = do_rsa_verify_spki;
  self->super.public_key = do_rsa_public_key;
  self->super.public_spki_key = do_rsa_public_spki_key;
}

static struct rsa_verifier *
make_rsa_verifier_internal(struct sexp_iterator *i)
{
  NEW(rsa_verifier, res);
  init_rsa_verifier(res);

  assert(SEXP_LEFT(i) >= 2);
  
  if (spki_init_rsa_verifier(&res->key, i))
    {
      return res;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}
  
/* Alternative constructor using a key of type ssh-rsa, when the atom
 * "ssh-rsa" is already read from the buffer. */
struct verifier *
parse_ssh_rsa_public(struct simple_buffer *buffer)
{
  NEW(rsa_verifier, res);
  init_rsa_verifier(res);

  if (parse_bignum(buffer, res->key.e, RSA_MAX_SIZE)
      && (mpz_sgn(res->key.e) == 1)
      && parse_bignum(buffer, res->key.n, RSA_MAX_SIZE)
      && (mpz_sgn(res->key.n) == 1)
      && (mpz_cmp(res->key.e, res->key.n) < 0)
      && parse_eod(buffer)
      && rsa_prepare_public_key(&res->key))
    return &res->super;

  else
    {
      KILL(res);
      return NULL;
    }
}

/* Signature creation */

static struct lsh_string *
do_rsa_sign(struct signer *s,
	    int algorithm,
	    UINT32 msg_length,
	    const UINT8 *msg)
{
  CAST(rsa_signer, self, s);
  struct lsh_string *res;
  struct sha1_ctx hash;
  mpz_t signature;

  trace("do_rsa_sign: Signing according to %a\n", algorithm);
  
  mpz_init(signature);
  sha1_init(&hash);
  sha1_update(&hash, msg_length, msg);

  rsa_sha1_sign(&self->key, &hash, signature);

  switch (algorithm)
    {
    case ATOM_SSH_RSA:
      /* Uses the encoding:
       *
       * string ssh-rsa
       * string signature-blob
       */
  
      res = ssh_format("%a%un", ATOM_SSH_RSA, signature);
      break;

      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:

      res = sexp_format(encode_rsa_sig_val(signature), SEXP_CANONICAL, 0);
      break;
    default:
      fatal("do_rsa_sign: Internal error!\n");
    }
  mpz_clear(signature);
  return res;
}

static struct sexp *
do_rsa_sign_spki(struct signer *s,
		 /* struct sexp *hash, struct sexp *principal, */
		 UINT32 msg_length,
		 const UINT8 *msg)
{
  CAST(rsa_signer, self, s);
  struct sha1_ctx hash;
  
  mpz_t x;
  struct sexp *signature;
  
  mpz_init(x);

  sha1_init(&hash);
  sha1_update(&hash, msg_length, msg);

  rsa_sha1_sign(&self->key, &hash, x);
  
  signature = encode_rsa_sig_val(x);
  
  mpz_clear(x);
  return signature;
}

static struct verifier *
do_rsa_get_verifier(struct signer *s)
{
  CAST(rsa_signer, self, s);

  return &self->verifier->super;
}

static struct verifier *
make_rsa_verifier(struct signature_algorithm *s UNUSED,
		  struct sexp_iterator *i)
{
  return ( (SEXP_LEFT(i) == 2)
	   ? &make_rsa_verifier_internal(i)->super
	   : NULL);
}


static struct signer *
make_rsa_signer(struct signature_algorithm *s UNUSED,
		struct sexp_iterator *i)
{
  NEW(rsa_signer, res);

  rsa_init_private_key(&res->key);

  /* The secret d is optional, it's not needed. */
  if ( (SEXP_LEFT(i) >= 7)
       && ( (res->verifier = make_rsa_verifier_internal(i)) )
       && sexp_get_un(i, ATOM_P, res->key.p, RSA_MAX_SIZE)
       && sexp_get_un(i, ATOM_Q, res->key.q, RSA_MAX_SIZE)
       && sexp_get_un(i, ATOM_A, res->key.a, RSA_MAX_SIZE)
       && sexp_get_un(i, ATOM_B, res->key.b, RSA_MAX_SIZE)
       && sexp_get_un(i, ATOM_C, res->key.c, RSA_MAX_SIZE) )
    {
      if (!rsa_prepare_private_key(&res->key)
	  || (res->key.size != res->verifier->key.size))
	{
	  KILL(res->verifier);
	  res->verifier = NULL;
	  KILL(res);

	  return NULL;
	}

      res->super.sign = do_rsa_sign;
      res->super.sign_spki = do_rsa_sign_spki;
      res->super.get_verifier = do_rsa_get_verifier;
      
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

struct signature_algorithm rsa_sha1_algorithm =
  { STATIC_HEADER, make_rsa_signer, make_rsa_verifier };

struct verifier *
make_ssh_rsa_verifier(UINT32 public_length,
		      const UINT8 *public)
{
  struct simple_buffer buffer;
  int atom;
  
  simple_buffer_init(&buffer, public_length, public);

  return ( (parse_atom(&buffer, &atom)
	    && (atom == ATOM_SSH_RSA))
	   ? parse_ssh_rsa_public(&buffer)
	   : NULL);
}
