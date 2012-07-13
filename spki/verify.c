/* Signature verification */

/* libspki
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The libspki library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The libspki library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the libspki library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <nettle/bignum.h>
#include <nettle/dsa.h>
#include <nettle/rsa.h>

#include "certificate.h"
#include "parse.h"

#define RSA_KEYSIZE_LIMIT 4096
/* Spec sets hard limit at 1024 resp. 3072, be a little more liberal. */
#define DSA_SHA1_KEYSIZE_LIMIT 2048
#define DSA_SHA256_KEYSIZE_LIMIT 4096


static int
spki_verify_rsa(int (*verify)(const struct rsa_public_key *key,
			      const uint8_t *digest,
			      const mpz_t signature),
		const uint8_t *digest,
		struct spki_iterator *key,
		struct spki_iterator *signature)
{
  struct rsa_public_key rsa;
  mpz_t s;
  int res;
  
  rsa_public_key_init(&rsa);
  mpz_init(s);

  res = (rsa_keypair_from_sexp_alist(&rsa, NULL,
				     RSA_KEYSIZE_LIMIT, &key->sexp)
	 && spki_parse_end(key)
	 && nettle_mpz_set_sexp(s, mpz_sizeinbase(rsa.n, 2),
				&signature->sexp)
	 && spki_parse_end(signature)
	 && verify(&rsa, digest, s));

  mpz_clear(s);
  rsa_public_key_clear(&rsa);
  return res;      
}

static int
spki_verify_dsa_sha1(const uint8_t *digest,
		     struct spki_iterator *key,
		     struct spki_iterator *signature)
{
  struct dsa_public_key dsa;
  struct dsa_signature rs;
  int res;

  dsa_public_key_init(&dsa);
  dsa_signature_init(&rs);

  res = (dsa_keypair_from_sexp_alist(&dsa, NULL,
				     DSA_SHA1_KEYSIZE_LIMIT,
				     DSA_SHA1_Q_BITS, &key->sexp)
	 && spki_parse_end(key)
	 && dsa_signature_from_sexp(&rs, &signature->sexp, DSA_SHA1_Q_BITS)
	 && dsa_sha1_verify_digest(&dsa, digest, &rs));

  dsa_signature_clear(&rs);
  dsa_public_key_clear(&dsa);

  return res;    
}

static int
spki_verify_dsa_sha256(const uint8_t *digest,
		       struct spki_iterator *key,
		       struct spki_iterator *signature)
{
  struct dsa_public_key dsa;
  struct dsa_signature rs;
  int res;

  dsa_public_key_init(&dsa);
  dsa_signature_init(&rs);

  res = (dsa_keypair_from_sexp_alist(&dsa, NULL,
				     DSA_SHA256_KEYSIZE_LIMIT,
				     DSA_SHA256_Q_BITS, &key->sexp)
	 && spki_parse_end(key)
	 && dsa_signature_from_sexp(&rs, &signature->sexp,
				    DSA_SHA256_Q_BITS)
	 && dsa_sha256_verify_digest(&dsa, digest, &rs));

  dsa_signature_clear(&rs);
  dsa_public_key_clear(&dsa);

  return res;    
}

int
spki_verify(void *ctx UNUSED,
	    const struct spki_hash_value *hash,
	    struct spki_principal *principal,
	    struct spki_iterator *signature)
{
  struct spki_iterator key;
  enum spki_type signature_type;
  
  if (!principal->key)
    /* Actual key not known */
    return 0;

  signature_type = signature->type;

  if (spki_iterator_first(&key, principal->key_length, principal->key)
      != SPKI_TYPE_PUBLIC_KEY)
    /* FIXME: Should not happen. Perhaps abort instead? */
    return 0;

  switch (spki_parse_type(&key))
    {
    case SPKI_TYPE_RSA_PKCS1_MD5:
      return (hash->type == SPKI_TYPE_MD5
	      && hash->length == MD5_DIGEST_SIZE
	      && signature_type == SPKI_TYPE_RSA_PKCS1_MD5
	      && spki_verify_rsa(rsa_md5_verify_digest,
				 hash->digest,
				 &key, signature));

    case SPKI_TYPE_RSA_PKCS1_SHA1:
      return (hash->type == SPKI_TYPE_SHA1
	      && hash->length == SHA1_DIGEST_SIZE
	      && signature_type == SPKI_TYPE_RSA_PKCS1_SHA1
	      && spki_verify_rsa(rsa_sha1_verify_digest, 
				 hash->digest,
				 &key, signature));
#if 0
    case SPKI_TYPE_RSA_PKCS1:
      /* What to do here? There seems to be three alternatives:
       *
       * 1. Allow either signature type, as long as it matches the
       *    digest type.
       *
       * 2. Allow signature type "rsa-pkcs1", and either hash type.
       *
       * 3. Require signature type "rsa-pkcs1", and use a hash
       *    identifier as part of the <sig-val>.
       *
       * It's not obvious what's right, so for now we don't allow any such
       * signatures at all.
       */
      return 0;
#endif
      
    case SPKI_TYPE_DSA_SHA1:
      return (hash->type == SPKI_TYPE_SHA1
	      && hash->length == SHA1_DIGEST_SIZE
	      && spki_verify_dsa_sha1(hash->digest, &key, signature));

    case SPKI_TYPE_SHA256:
      return (hash->type == SPKI_TYPE_SHA256
	      && hash->length == SHA256_DIGEST_SIZE
	      && spki_verify_dsa_sha256(hash->digest, &key, signature));
      
    default:
      return 0;
    }
}
