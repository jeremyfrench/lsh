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

#include "dsa.h"

#include "atoms.h"
/* #include "crypto.h" */
#include "format.h"
#include "parse.h"
#include "randomness.h"
#include "sexp.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/sha.h"
#include "nettle/dsa.h"

#include <assert.h>

#include "dsa.c.x" 

/* The standard says that DSA public keys are at most 1024 bits, i.e.
 * 128 octets. We are a little more liberal than that. Note that
 * allowing really large keys opens for Denial-of-service attacks. */

#define DSA_MAX_SIZE 300

#define DSA_MAX_QSIZE SHA1_DIGEST_SIZE

#define SA(x) sexp_a(ATOM_##x)

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

/* FIXME: Use nettle's sexp functions. */
static struct sexp *
encode_dsa_sig_val(const struct dsa_signature *signature)
{
  return sexp_l(2, sexp_l(2, SA(R), sexp_un(signature->r), -1),
		sexp_l(2, SA(S), sexp_un(signature->s), -1), -1);
}

static int
decode_dsa_sig_val(struct sexp *e, struct dsa_signature *signature)
{
  if (sexp_atomp(e))
    return 0;
  else
    {
      struct sexp_iterator *i = SEXP_ITER(e);
      return ( (SEXP_LEFT(i) == 2)
	       && sexp_get_un(i, ATOM_R, signature->r, DSA_MAX_QSIZE)
	       && sexp_get_un(i, ATOM_S, signature->s, DSA_MAX_QSIZE));
    }
}


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
	      && (buf_length <= (2 * DSA_MAX_QSIZE))
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
	     || (signature_length > (2 * DSA_MAX_QSIZE)) )
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
	struct simple_buffer buffer;
	struct sexp *e;
	
	simple_buffer_init(&buffer, signature_length, signature_data);
	
	if (! ( (e = sexp_parse_canonical(&buffer))
		&& parse_eod(&buffer)
		&& decode_dsa_sig_val(e, &sv)) )
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

static struct sexp *
do_dsa_public_spki_key(struct verifier *s)
{
  CAST(dsa_verifier, self, s);

  return sexp_l(5, SA(DSA),
		sexp_l(2, SA(P), sexp_un(self->key.p), -1),
		sexp_l(2, SA(Q), sexp_un(self->key.q), -1),
		sexp_l(2, SA(G), sexp_un(self->key.g), -1),
		sexp_l(2, SA(Y), sexp_un(self->key.y), -1),
		-1);
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

static struct dsa_verifier *
make_dsa_verifier_internal(struct sexp_iterator *i)
{
  NEW(dsa_verifier, res);
  init_dsa_verifier(res);

  assert(SEXP_LEFT(i) >= 4);

  if (sexp_get_un(i, ATOM_P, res->key.p, DSA_MAX_SIZE)
      && sexp_get_un(i, ATOM_Q, res->key.q, DSA_MAX_QSIZE)
      && sexp_get_un(i, ATOM_G, res->key.g, DSA_MAX_SIZE)
      && sexp_get_un(i, ATOM_Y, res->key.y, DSA_MAX_SIZE))
    {
      return res;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}
  
/* Alternative constructor using a key of type ssh-dss, when the atom
 * "ssh-dss" is already read from the buffer. */
struct verifier *
parse_ssh_dss_public(struct simple_buffer *buffer)
{
  NEW(dsa_verifier, res);
  init_dsa_verifier(res);

  if (parse_bignum(buffer, res->key.p, DSA_MAX_SIZE)
      && (mpz_sgn(res->key.p) == 1)
      && parse_bignum(buffer, res->key.q, DSA_MAX_QSIZE)
      && (mpz_sgn(res->key.q) == 1)
      && (mpz_cmp(res->key.q, res->key.p) < 0) /* q < p */ 
      && parse_bignum(buffer, res->key.g, DSA_MAX_SIZE)
      && (mpz_sgn(res->key.g) == 1)
      && (mpz_cmp(res->key.g, res->key.p) < 0) /* g < p */ 
      && parse_bignum(buffer, res->key.y, DSA_MAX_SIZE) 
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
      /* NOTE: Generates the <sig-val> only. */
      signature
	= sexp_format(encode_dsa_sig_val(&sv),
		      SEXP_CANONICAL, 0);
      
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
  return ( (SEXP_LEFT(i) == 4)
	   ? &make_dsa_verifier_internal(i)->super
	   : NULL);
}

static struct signer *
make_dsa_signer(struct signature_algorithm *c,
		struct sexp_iterator *i)
{
  CAST(dsa_algorithm, self, c);
  NEW(dsa_signer, res);

  dsa_private_key_init(&res->key);

#if 0
  debug("make_dsa_signer: SEXP_LEFT(i) == %i\n");
  debug("make_dsa_signer: SEXP_GET(i) == %fS\n",
	sexp_format(SEXP_GET(i), SEXP_ADVANCED, 0));
#endif
  
  if ( (SEXP_LEFT(i) == 5)
       && ( (res->verifier = make_dsa_verifier_internal(i)) )
       && sexp_get_un(i, ATOM_X, res->key.x, DSA_MAX_QSIZE) )
    {
      res->random = self->random;
      res->super.sign = do_dsa_sign;
      res->super.get_verifier = do_dsa_get_verifier;
      
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
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
