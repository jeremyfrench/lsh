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

#include "rsa.c.x"

/* GABA:
   (class
     (name rsa_algorithm)
     (super signature_algorithm)
     (vars
       (hash object hash_algorithm)

       ; The complete prefix for a DigestInfo, including the algorithm
       ; identifier for the hash function. A DigestInfo is formed by
       ; cetenating this prefix with the raw hash value.
       (prefix_length . UINT32)
       (prefix . "const UINT8 *")))
*/

#define STATIC_RSA_ALGORITHM(a, l, id) \
{ { STATIC_HEADER, make_rsa_signer, make_rsa_verifier }, \
  a, l, id }

static void
pkcs_1_encode(mpz_t m,
	      struct rsa_algorithm *params,
	      UINT32 length,
	      UINT32 msg_length,
	      UINT8 *msg)
{
  UINT8 *em = alloca(length);
  unsigned i = length;
  unsigned pad;
  
  struct hash_instance *h = MAKE_HASH(params->hash);
  HASH_UPDATE(h, msg_length, msg);

  assert(i >= h->hash_size);
  i -= h->hash_size;

  HASH_DIGEST(h, em + i);
  KILL(h);

  assert(i >= params->prefix_length);
  i -= params->prefix_length;

  memcpy(em + i, params->prefix, params->prefix_length);

  assert(i);
  em[--i] = 0;

  assert(i >= 9);
  em[0] = 1;
  memset(em + 1, 0xff, i - 1);
  
  bignum_parse_u(m, length, em);
}

/* GABA:
   (struct
     (name rsa_public)
     (vars
       (params object rsa_algorithm)
       (size . unsigned)
       (n bignum)
       (e bignum)))
*/

/* FIXME: The allocator could do this kind of initialization
 * automatically. */
static void
init_rsa_public(struct rsa_public *public, struct rsa_algorithm *params)
{
  public->params = params;
  mpz_init(public->n);
  mpz_init(public->e);
}

static int rsa_check_size(struct rsa_public *key)
{
  /* Size in octets */
  key->size = (mpz_sizeinbase(key->n, 2) + 7) / 8;

  /* PKCS#1 to make sense, the size of the modulo, in octets, must be
   * at least 1 + the length of the DER-encoded Digest Info.
   *
   * And a DigestInfo is 34 octets for md5, and 35 octets for sha1.
   * 46 octets is 368 bits.
   */
  return (key->size >= 46);
}

static int
spki_init_rsa_public(struct rsa_public *key,
		     struct sexp_iterator *i)
{
  return (sexp_get_un(i, ATOM_N, key->n)
	  && sexp_get_un(i, ATOM_E, key->e)
	  && rsa_check_size(key));
}

/* GABA:
   (class
     (name rsa_verifier)
     (super verifier)
     (vars
       (public struct rsa_public)))
*/

/* GABA:
   (class
     (name rsa_signer)
     (super signer)
     (vars
       (public struct rsa_public)

       ; Secret exponent
       (d bignum)

       ; The two factors
       (p bignum)
       (q bignum)

       ; d % (p-1), i.e. ae = 1 (mod p)
       (a bignum)

       ; d % (q-1), i.e. be = 1 (mod q)
       (b bignum)

       ; modular inverse of q , i.e. cq = 1 (mod p)
       (c bignum)))
*/


static struct lsh_string *
do_rsa_sign(struct signer *s,
	    UINT32 msg_length,
	    UINT8 *msg)
{
  CAST(rsa_signer, self, s);
  struct lsh_string *s;
  mpz_t m;

  mpz_init(m);
  pkcs_1_encode(m, self->params, self->public->size - 1,
		msg_length, msg);

  /* FIXME: Optimize using CRT */
  mpz_powm(m, m, self->d, self->public->m);
  
  s = ssh_format("%lun", m);

  mpz_clear(m);
  return s;
}

static struct sexp *
do_rsa_sign_spki(struct signer *s,
		 struct sexp *hash, struct sexp *principal,
		 UINT32 msg_length,
		 UINT8 *msg)
{
  fatal("do_rsa_sign_spki() not implemented.\n");
  
}

static struct sexp *
do_rsa_public_key(struct signer *s)
{
  CAST(rsa_signer, self, s);

  return sexp_l(2, sexp_a(ATOM_PUBLIC_KEY),
		sexp_l(3, sexp_a(ATOM_RSA_PKCS1),
		       sexp_l(2, sexp_a(ATOM_N), sexp_un(self->public.n), -1),
		       sexp_l(2, sexp_a(ATOM_E), sexp_un(self->public.e), -1),
		       -1), -1);
}

static int
do_rsa_verify(struct verifier *s,
	      UINT32 length,
	      UINT8 *msg,
	      UINT32 signature_length,
	      UINT8 * signature_data)
{
  CAST(rsa_verifier, self, s);
  mpz_t m;
  mpz_t s;
  int res;
  
  if (signature_length > self->public.size)
    return 0;
  
  mpz_init(s);
  bignum_parse_u(s, signature_length, signature_data);

  if (mpz_cmp_u(s, self->public.n) >= 0)
    {
      mpz_clear(s);
      return 0;
    }

  mpz_powm(s, s, self->public.e, self->public.n);

  mpz_init(m);
  pkcs_1_encode(m, self->public->params, self->public->size,
		length, msg);
  
  res = !mpz_cmp(m, s);
  mpz_clear(m); mpz_clear(s);

  return res;
}

static int
do_rsa_verify_spki(struct verifier *s,
		   UINT32 length,
		   UINT8 *msg,
		   struct sexp_iterator *i)
{
  fatal("do_rsa_verify_spki() not implemented.\n");
}

static struct signer *
make_rsa_signer(struct signature_algorithm *s,
		struct sexp_iterator *i)
{
  CAST(rsa_algorithm, params, s);
  NEW(rsa_verifier, res);
  init_rsa_public(&res->public, params);

  if ( (SEXP_LEFT(i) >= 3)
       && spki_init_rsa_public(&res->public, i)
       && sexp_get_un(i, ATOM_d, res->d) )
    {
      res->super.sign = do_rsa_sign;
      res->super.sign_spki = do_rsa_sign_spki;
      res->super.public_key = do_rsa_public_key;
      
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

static struct verifier *
make_rsa_verifier(struct signature_algorithm *s,
		  struct sexp_iterator *i)
{
  CAST(rsa_algorithm, params, s);
  NEW(rsa_verifier, res);
  init_rsa_public(&res->public, params);

  if ( (SEXP_LEFT(i) == 2)
       && spki_init_rsa_public(&res->public, i))
    {
      res->super.verify = do_rsa_verify;
      res->super.verify_spki = do_rsa_verify_spki;
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

struct signature_algorithm *
make_rsa_algorithm(struct hash_algorithm *hash,
		   UINT32 prefix_length,
		   const UINT8 *prefix)
{
  NEW(rsa_algorithm, self);
  self->super.make_signer = make_rsa_signer;
  self->super.make_verifier = make_rsa_verifier;
  self->hash = hash;
  self->hashid = hashid;

  return &self->super;
}

/* From pkcs-1v2
 *
 *   md5 OBJECT IDENTIFIER ::=
 *     {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5}
 *
 * The parameters part of the algorithm identifier is NULL:
 *
 *   md5Identifier ::= AlgorithmIdentifier {md5, NULL}
 */

static const UINT8 md5_prefix[] =
{
  /* 18 octets prefic 16 octets hash, 34 total. */
  0x30,       32, /* SEQUENCE */
    0x30,     12, /* SEQUENCE */
      0x06,    8, /* OBJECT IDENTIFIER */
  	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
      0x05,    0, /* NULL */
    0x04,     16  /* OCTET STRING */
      /* Here comes the raw hash value */
};

struct rsa_algorithm rsa_md5_algorithm =
STATIC_RSA_ALGORITHM(&md5_algorithm, md5_prefix, 18);

/* From pkcs-1v2
 *
 *   id-sha1 OBJECT IDENTIFIER ::=
 *     {iso(1) identified-organization(3) oiw(14) secsig(3)
 *   	 algorithms(2) 26}
 *   
 *   The default hash function is SHA-1: 
 *   sha1Identifier ::= AlgorithmIdentifier {id-sha1, NULL}
 */

static const UINT8 sha1_prefix[] =
{
  /* 15 octets prefix, 20 octets hash, total 35 */
  0x30,       33, /* SEQUENCE */
    0x30,      9, /* SEQUENCE */
      0x06,    5, /* OBJECT IDENTIFIER */
  	  0x2b, 0x0e, 0x03, 0x02, 0x1a,
      0x05,    0, /* NULL */
    0x04,     20  /* OCTET STRING */
      /* Here comes the raw hash value */
};

strust rsa_algorithm rsa_sha1_algorithm =
STATIC_RSA_ALGORITHM(&sha1_algorithm, sha1_prefix, 15);

