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
#include "format.h"
#include "parse.h"
#include "randomness.h"
#include "sexp.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/bignum.h"
#include "nettle/dsa.h"
#include "nettle/sexp.h"
#include "nettle/sha.h"

#include <assert.h>

#include "dsa.c.x" 

/* The standard says that DSA public keys are at most 1024 bits, i.e.
 * 128 octets. We are a little more liberal than that. Note that
 * allowing really large keys opens for Denial-of-service attacks. */

#define DSA_MAX_OCTETS 256
#define DSA_MAX_BITS (8 * DSA_MAX_OCTETS)

/* DSA signatures */

/* GABA:
   (class
     (name dsa_algorithm)
     (super signature_algorithm)
     (vars
       (random object randomness)))
*/

/* GABA:
   (class
     (name dsa_verifier)
     (super verifier)
     (vars
       (key indirect-special "struct dsa_public_key"
            #f dsa_public_key_clear)))
*/

/* GABA:
   (class
     (name dsa_signer)
     (super signer)
     (vars
       (verifier object dsa_verifier)
       (random object randomness)
       (key indirect-special "struct dsa_private_key"
            #f dsa_private_key_clear)))
*/

/* FIXME: Delete function. */
/* Verifying DSA signatures */
/* The caller should make sure that r and s are non-negative, and not
 * extremely large. That they are less than q is checked here. */
static int
generic_dsa_verify(struct dsa_verifier *key,
		   UINT32 length,
		   const UINT8 *msg,
		   const struct dsa_signature *signature)
{
  struct sha1_ctx hash;
  sha1_init(&hash);
  sha1_update(&hash, length, msg);

  return dsa_verify(&key->key, &hash, signature);
}

static int
do_dsa_verify(struct verifier *c, int algorithm,
	      UINT32 length,
	      const UINT8 *msg,
	      UINT32 signature_length,
	      const UINT8 *signature_data)
{
  CAST(dsa_verifier, self, c);
  struct simple_buffer buffer;

  int res = 0;

  struct dsa_signature sv;

  trace("do_dsa_verify: Verifying %a signature\n", algorithm);
  dsa_signature_init(&sv);
  
  switch (algorithm)
    {
    case ATOM_SSH_DSS:
      {
	/* NOTE: draft-ietf-secsh-transport-X.txt (x <= 07) uses an extra
	 * length field, which should be removed in the next version. */
	
	UINT32 buf_length;
	const UINT8 *buf;
	int atom;
      
	simple_buffer_init(&buffer, signature_length, signature_data);
	if (!(parse_atom(&buffer, &atom)
	      && (atom == ATOM_SSH_DSS)
	      && parse_string(&buffer, &buf_length, &buf)
	      && !(buf_length % 2)
	      && (buf_length <= (2 * DSA_Q_OCTETS))
	      && parse_eod(&buffer)))
	  goto fail;

	buf_length /= 2;
  
	bignum_parse_u(sv.r, buf_length, buf);
	bignum_parse_u(sv.s, buf_length, buf + buf_length);

	break;
      }

#if DATAFELLOWS_WORKAROUNDS
    case ATOM_SSH_DSS_KLUDGE_LOCAL:
      {
	UINT32 buf_length;

	/* NOTE: This doesn't include any length field. Is that right? */

	if ( (signature_length % 2)
	     || (signature_length > (2 * DSA_Q_OCTETS)) )
	  goto fail;

	buf_length = signature_length / 2;

	bignum_parse_u(sv.r, buf_length, signature_data);
	bignum_parse_u(sv.s, buf_length, signature_data + buf_length);
	break;
      }
#endif
      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:
    case ATOM_SPKI:
      {
	struct sexp_iterator i;
	
	const uint8_t *names[2] = { "r", "s" };
	struct sexp_iterator values[2];
	
	if (! (sexp_iterator_first(&i, signature_length,  signature_data)
	       && sexp_iterator_enter_list(&i)
	       && sexp_iterator_assoc(&i, 2, names, values)
	       && nettle_mpz_set_sexp(sv.r, DSA_Q_BITS, &values[0])
	       && nettle_mpz_set_sexp(sv.s, DSA_Q_BITS, &values[1])) )
	  goto fail;

	break;
      }
    default:
      fatal("do_dsa_verify: Internal error!\n");
    }
  res = generic_dsa_verify(self, length, msg, &sv);
 fail:

  dsa_signature_clear(&sv);

  return res;
}


static struct lsh_string *
do_dsa_public_key(struct verifier *s)
{
  CAST(dsa_verifier, self, s);
  return ssh_format("%a%n%n%n%n",
		    ATOM_SSH_DSS,
		    self->key.p, self->key.q,
		    self->key.g, self->key.y);
}

static struct lsh_string *
do_dsa_public_spki_key(struct verifier *s, int transport)
{
  CAST(dsa_verifier, self, s);

  return lsh_sexp_format(transport,
			 "(%z(%z(%z%b)(%z%b)(%z%b)(%z%b)))",
			 "public-key",  "dsa",
			 "p", self->key.p,
			 "q", self->key.q,
			 "g", self->key.g,
			 "y", self->key.y);
}

static void
init_dsa_verifier(struct dsa_verifier *self)
{
  /* FIXME: The allocator could do this kind of initialization
   * automatically. */
  dsa_public_key_init(&self->key);

  self->super.verify = do_dsa_verify;
  self->super.public_spki_key = do_dsa_public_spki_key;
  self->super.public_key = do_dsa_public_key;
}


/* Alternative constructor using a key of type ssh-dss, when the atom
 * "ssh-dss" is already read from the buffer. */
struct verifier *
parse_ssh_dss_public(struct simple_buffer *buffer)
{
  NEW(dsa_verifier, res);
  init_dsa_verifier(res);

  if (parse_bignum(buffer, res->key.p, DSA_MAX_OCTETS)
      && (mpz_sgn(res->key.p) == 1)
      && parse_bignum(buffer, res->key.q, DSA_Q_OCTETS)
      && (mpz_sgn(res->key.q) == 1)
      && (mpz_cmp(res->key.q, res->key.p) < 0) /* q < p */ 
      && parse_bignum(buffer, res->key.g, DSA_MAX_OCTETS)
      && (mpz_sgn(res->key.g) == 1)
      && (mpz_cmp(res->key.g, res->key.p) < 0) /* g < p */ 
      && parse_bignum(buffer, res->key.y, DSA_MAX_OCTETS) 
      && (mpz_sgn(res->key.y) == 1)
      && (mpz_cmp(res->key.y, res->key.p) < 0) /* y < p */
      && parse_eod(buffer))
    
    return &res->super;

  else
    {
      KILL(res);
      return NULL;
    }
}

  
/* Creating signatures */
/* FIXME: Delete function. */
static void
generic_dsa_sign(struct dsa_signer *self,
		 UINT32 length, const UINT8 *msg,
		 struct dsa_signature *signature)
{
  struct sha1_ctx hash;
  sha1_init(&hash);
  sha1_update(&hash, length, msg);

  dsa_sign(&self->verifier->key, &self->key,
	   self->random, lsh_random,
	   &hash, signature);
}

static UINT32
dsa_blob_length(const struct dsa_signature *signature)
{
  UINT32 r_length = bignum_format_u_length(signature->r);
  UINT32 s_length = bignum_format_u_length(signature->s);

  return MAX(r_length, s_length);
}

static void
dsa_blob_write(const struct dsa_signature *signature,
	       UINT32 length, UINT8 *buf)
{
  bignum_write(signature->r, length, buf);
  bignum_write(signature->s, length, buf + length);
}

static struct lsh_string *
do_dsa_sign(struct signer *c,
	    int algorithm,
	    UINT32 msg_length,
	    const UINT8 *msg)
{
  CAST(dsa_signer, self, c);
  struct dsa_signature sv;
  struct lsh_string *signature;
  UINT32 buf_length;
  UINT8 *p;

  trace("do_dsa_sign: Signing according to %a\n", algorithm);

  dsa_signature_init(&sv);
  generic_dsa_sign(self, msg_length, msg, &sv);

  debug("do_dsa_sign: r = %xn, s = %xn\n", sv.r, sv.s);
  
  /* Build signature */
  buf_length = dsa_blob_length(&sv);

  switch (algorithm)
    {
    case ATOM_SSH_DSS:
      /* NOTE: draft-ietf-secsh-transport-X.txt (x <= 07) uses an extra
       * length field, which should be removed in the next version. */
      signature = ssh_format("%a%r", ATOM_SSH_DSS, buf_length * 2, &p);
      dsa_blob_write(&sv, buf_length, p);

      break;
      
#if DATAFELLOWS_WORKAROUNDS
    case ATOM_SSH_DSS_KLUDGE_LOCAL:
      
      /* NOTE: This doesn't include any length field. Is that right? */
      signature = ssh_format("%lr", buf_length * 2, &p);
      dsa_blob_write(&sv, buf_length, p);

      break;

#endif
      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:
    case ATOM_SPKI:
      /* Format: "((1:r20:<r>)(1:s20:<s>))". */
      signature = lsh_sexp_format(0, "((%z%b)(%z%b))",
				  "r", sv.r, "s", sv.s);
	
      break;
    default:
      fatal("do_dsa_sign: Internal error, unexpected algorithm %a.\n",
	    algorithm);
    }
  dsa_signature_clear(&sv);

  return signature;
}

static struct verifier *
do_dsa_get_verifier(struct signer *s)
{
  CAST(dsa_signer, self, s);
  return &self->verifier->super;
}


static struct verifier *
make_dsa_verifier(struct signature_algorithm *self UNUSED,
		  struct sexp_iterator *i)
{
  NEW(dsa_verifier, res);
  init_dsa_verifier(res);

  if (dsa_keypair_from_sexp_alist(&res->key, NULL, DSA_MAX_BITS, i))
    return &res->super;

  KILL(res);
  return NULL;
}

static struct signer *
make_dsa_signer(struct signature_algorithm *c,
		struct sexp_iterator *i)
{
  CAST(dsa_algorithm, self, c);
  NEW(dsa_verifier, verifier);
  NEW(dsa_signer, res);

  init_dsa_verifier(verifier);
  
  dsa_private_key_init(&res->key);

  if (dsa_keypair_from_sexp_alist(&verifier->key, &res->key, DSA_MAX_BITS, i))
    {
      res->random = self->random;
      res->verifier = verifier;
      res->super.sign = do_dsa_sign;
      res->super.get_verifier = do_dsa_get_verifier;
      
      return &res->super;
    }

  KILL(res);
  KILL(verifier);
  return NULL;
}

struct signature_algorithm *
make_dsa_algorithm(struct randomness *random)
{
  NEW(dsa_algorithm, dsa);

  dsa->super.make_signer = make_dsa_signer;
  dsa->super.make_verifier = make_dsa_verifier;
  dsa->random = random;

  return &dsa->super;
}


struct verifier *
make_ssh_dss_verifier(UINT32 public_length,
		      const UINT8 *public)
{
  struct simple_buffer buffer;
  int atom;
  
  simple_buffer_init(&buffer, public_length, public);

  return ( (parse_atom(&buffer, &atom)
	    && (atom == ATOM_SSH_DSS))
	   ? parse_ssh_dss_public(&buffer)
	   : NULL);
}
