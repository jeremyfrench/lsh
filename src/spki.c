/* spki.c
 *
 * An implementation of SPKI certificate checking
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2003 Balázs Scheidler, Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "nettle/sexp.h"

#include "spki/parse.h"
#include "spki/tag.h"

#include "spki.h"

#include "atoms.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "interact.h"
#include "list.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "randomness.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"
#include "alist.h"


/* Forward declarations */
static void
do_spki_acl_db_mark(struct spki_acl_db *db,
		     void (*mark)(struct lsh_object *o));

static void
do_spki_acl_db_free(struct spki_acl_db *db);

#define GABA_DEFINE
# include "spki.h.x"
#undef GABA_DEFINE


/* FIXME: This should create different tags for hostnames that are not
 * dns fqdn:s. */

struct lsh_string *
make_ssh_hostkey_tag(const char *host)
{
  uint32_t left = strlen(host);
  const uint8_t *s = host;
  struct lsh_string *tag;
  struct lsh_string *reversed = lsh_string_alloc(left);

  /* First, transform "foo.lysator.liu.se" into "se.liu.lysator.foo" */
  while (left)
    {
      uint8_t *p = memchr(s, '.', left);
      if (!p)
	{
	  memcpy(reversed->data, s, left);
	  break;
	}
      else
	{
	  uint32_t segment = p - s;
	  left -= segment;

	  memcpy(reversed->data + left, s, segment);
	  reversed->data[--left] = '.';
	  s = p+1;
	}
    }

  tag = lsh_sexp_format(0, "(tag(ssh-hostkey%s))",
			reversed->length, reversed->data);
  lsh_string_free(reversed);

  return tag;
}      

/* Syntax: (<algorithm> ...). Advances the iterator passed the algorithm
 * identifier, and returns the corresponding algorithm. */
static const struct lsh_object *
spki_algorithm_lookup(struct alist *algorithms,
		      struct sexp_iterator *i,
		      int *type)
{
  struct lsh_object *res;
  int algorithm_name = lsh_sexp_get_type(i);
  
  /* FIXME: Display a pretty message if lookup fails. */
  res = ALIST_GET(algorithms, algorithm_name);

  if (res && type)
    *type = algorithm_name;

  return res;
}

struct verifier *
spki_make_verifier(struct alist *algorithms,
		   struct sexp_iterator *i)
{
  /* Syntax: (<algorithm> <s-expr>*) */
  struct signature_algorithm *algorithm;
  struct verifier *v;

  {
    CAST_SUBTYPE(signature_algorithm, a, 
		 spki_algorithm_lookup(algorithms, i, NULL));
    algorithm = a;
  }
  
  if (!algorithm)
    return NULL;

  v = MAKE_VERIFIER(algorithm, i);
  
  if (!v)
    {
      werror("spki_make_verifier: Invalid public-key data.\n");
      return NULL;
    }
  
  return v;
}

/* Returns the algorithm type, or zero on error. */
struct signer *
spki_sexp_to_signer(struct alist *algorithms,
		    struct sexp_iterator *i,
		    int *type)
{
  /* Syntax: (<algorithm> <s-expr>*) */
  struct signature_algorithm *algorithm;

  {
    CAST_SUBTYPE(signature_algorithm, a, 
		 spki_algorithm_lookup(algorithms, i, type));
    algorithm = a;
  }

  return algorithm ? MAKE_SIGNER(algorithm, i) : NULL;
}

/* Reading keys */

/* NOTE: With transport syntax */

struct signer *
spki_make_signer(struct alist *algorithms,
		 const struct lsh_string *key,
		 int *algorithm_name)
{
  struct sexp_iterator i;
  uint8_t *decoded;  

  decoded = alloca(key->length);
  memcpy(decoded, key->data, key->length);
  
  if (sexp_transport_iterator_first(&i, key->length, decoded)
      && sexp_iterator_check_type(&i, "private-key"))
    return spki_sexp_to_signer(algorithms, &i, algorithm_name);

  werror("spki_make_signer: Expected private-key expression.\n");
  return NULL;
}

struct lsh_string *
spki_hash_data(const struct hash_algorithm *algorithm,
	       int algorithm_name,
	       uint32_t length, uint8_t *data)
{
  struct hash_instance *hash = make_hash(algorithm);
  uint8_t *out = alloca(HASH_SIZE(hash));

  hash_update(hash, length, data);
  hash_digest(hash, out);

  return lsh_sexp_format(0, "(hash%0s%s)",
			 "hash", get_atom_name(algorithm_name),
			 HASH_SIZE(hash), out);
}  

static void
do_spki_acl_db_mark(struct spki_acl_db *db,
		    void (*mark)(struct lsh_object *o))
{
  struct spki_principal *p;

  for (p = db->first_principal; p; p = p->next)
    mark(p->verifier);
}

static void
do_spki_acl_db_free(struct spki_acl_db *db)
{
  spki_acl_clear(db);
}

/* FIXME: This functions seems a little redundant. Perhaps change it
 * to take a string argument, and let it loop over an acl list? Then
 * lsh.c need no longer include spki/parse.h. */
int
spki_add_acl(struct spki_context *ctx,
             struct spki_iterator *i)
{
  return spki_acl_process(&ctx->db, i);
}

struct spki_principal *
spki_lookup(struct spki_context *self,
	    unsigned length,
	    const uint8_t *key,
	    struct verifier *v)

{
  struct spki_principal *principal;
  struct spki_iterator i;
  struct sexp_iterator sexp;

  if (!sexp_iterator_first(&sexp, length, key)
      || !spki_iterator_first_sexp(&i, &sexp)
      || !spki_parse_principal(&self->db, &i, &principal))
    {
      werror("do_spki_lookup: Invalid expression.\n");
      return NULL;
    }

  if (!principal->verifier)
    {
      if (v)
	principal->verifier = v;
      else
	principal->verifier = spki_make_verifier(self->algorithms, &sexp);
    }
  
  return principal;
}

int
spki_authorize(struct spki_context *self,
	       const struct spki_principal *user,
	       time_t t,
	       const struct lsh_string *access)
{
  const struct spki_5_tuple *acl;
  struct spki_date date;
  struct spki_tag *tag;
  struct spki_iterator i;
  const struct spki_5_tuple_list *p;
  
  if (!spki_iterator_first(&i, access->length, access->data)
      || !spki_parse_tag(&self->db, &i, &tag))
    {
      werror("spki_authorize: Invalid tag.\n");
      return 0;
    }

  spki_date_from_time_t(&date, t);
  
  for (acl = spki_acl_by_subject_first(&self->db, &p, user);
       acl;
       acl = spki_acl_by_subject_next(&p, user))
    {
      if (spki_tag_includes(acl->tag, tag)
	  && SPKI_DATE_CMP(acl->not_before, date) <= 0
	  && SPKI_DATE_CMP(acl->not_after, date) >= 0)
	{
	  spki_tag_free(&self->db, tag);
	  return 1;
	}
    }
  spki_tag_free(&self->db, tag);

  return 0;
}

struct spki_context *
make_spki_context(struct alist *algorithms)
{
  NEW(spki_context, self);
  
  self->algorithms = algorithms;
  /* FIXME: Use lsh allocation functions. */
  spki_acl_init(&self->db);
  
  return self;
}

/* PKCS-5 handling */

/* Encryption of private data.
 * For PKCS#5 (version 2) key derivation, we use
 *
 * (password-encrypted LABEL
 *   (Xpkcs5v2 hmac-sha1 (salt #...#)
 *                       (iterations #...#))
 *   ("3des-cbc" (iv #...#) (data #...#)))
 *
 * where the X:s will be removed when the format is more stable.
 *
 */

struct lsh_string *
spki_pkcs5_encrypt(struct randomness *r,
                   struct lsh_string *label,
		   uint32_t prf_name,
		   struct mac_algorithm *prf,
		   int crypto_name,
		   struct crypto_algorithm *crypto,
		   uint32_t salt_length,
		   struct lsh_string *password,
		   uint32_t iterations,
                   struct lsh_string *data)
{
  struct lsh_string *key;
  struct lsh_string *salt;
  struct lsh_string *iv;
  struct lsh_string *encrypted;
  struct lsh_string *value;
  
  assert(crypto);
  assert(prf);

  /* NOTE: Allows random to be of bad quality */
  salt = lsh_string_alloc(salt_length);
  RANDOM(r, salt->length, salt->data);
    
  key = lsh_string_alloc(crypto->key_size);

  pkcs5_derive_key(prf,
		   password->length, password->data,
		   salt->length, salt->data,
		   iterations,
		   key->length, key->data);

  if (crypto->iv_size)
    {
      iv = lsh_string_alloc(crypto->iv_size);
      RANDOM(r, iv->length, iv->data);
    }
  else
    iv = NULL;

  encrypted = crypt_string_pad(MAKE_ENCRYPT(crypto,
					    key->data,
					    iv ? iv->data : NULL),
			       data, 0);
  
  /* FIXME: Handle iv == NULL. */
  value = lsh_sexp_format(0, "(password-encrypted%s(xpkcs5v2%0s"
			  "(iterations%i)(salt%s))"
			  "(%0s(iv%s)(data%s)))",
			  label->length, label->data,
			  get_atom_name(prf_name),
			  iterations,
			  salt->length, salt->data,
			  get_atom_name(crypto_name),
			  iv->length, iv->data,
			  encrypted->length, encrypted->data);

  lsh_string_free(key);
  lsh_string_free(salt);
  lsh_string_free(iv);
  lsh_string_free(encrypted);

  return value;
}

/* Frees input string. */
struct lsh_string *
spki_pkcs5_decrypt(struct alist *mac_algorithms,
                   struct alist *crypto_algorithms,
                   struct interact *interact,
                   struct lsh_string *expr)
{
  struct sexp_iterator i;
  
  if (! (sexp_iterator_first(&i, expr->length, expr->data)
	 && sexp_iterator_check_type(&i, "password-encrypted")))
    return expr;

  else
    {
      struct sexp_iterator key_info;

      struct crypto_algorithm *crypto;
      struct mac_algorithm *mac;

      const struct lsh_string *label = NULL;
      const struct lsh_string *salt = NULL;
      const struct lsh_string *iv = NULL;
      const struct lsh_string *data = NULL;
      uint32_t iterations;
      
      /* NOTE: This is a place where it might make sense to use a sexp
       * display type, but we don't support that for now. */
      label = lsh_sexp_to_string(&i, NULL);

      if (!label)
	{
	  werror("Invalid label in (password-encrypted ...) expression.\n");
	fail:
	  lsh_string_free(data);
	  lsh_string_free(expr);
	  lsh_string_free(iv);
	  lsh_string_free(salt);
	  lsh_string_free(label);
	  return NULL;
	}

      key_info = i;

      /* Examine the payload expression first, before asking for a
       * pass phrase. */

      if (!sexp_iterator_next(&i))
	goto fail;

      if (sexp_iterator_enter_list(&i))
	goto fail;
      
      {
	const uint8_t *names[2] = { "data", "iv" };
	struct sexp_iterator values[2];

	CAST_SUBTYPE(crypto_algorithm, tmp,
		     spki_algorithm_lookup(crypto_algorithms, &i, NULL));
	
	crypto = tmp;

	if (!crypto)
	  {
	    werror("Unknown encryption algorithm for pkcs5v2.\n");
	    goto fail;
	  }

	if (!sexp_iterator_assoc(&i, crypto->iv_size ? 2 : 1,
				 names, values))
	  goto fail;

	data = lsh_sexp_to_string(&values[0], NULL);
	iv = crypto->iv_size ? lsh_sexp_to_string(&values[1], NULL) : NULL;
      }
	
      if (crypto->iv_size)
	{
	  if (!iv || (iv->length != crypto->iv_size))
	    {
	      werror("Invalid IV for pkcs5v2.\n");
	      goto fail;
	    }
	}
      else if (iv)
	{
	  if (iv->length)
	    {
	      werror("Unexpected iv provided for pkcs5v2.\n");
	      goto fail;
	    }
	  lsh_string_free(iv);
	  iv = NULL;
	}
	
      if (crypto->block_size && (data->length % crypto->block_size))
	{
	  werror("Payload data doesn't match block size for pkcs5v2.\n");
	  goto fail;
	}

      /* Get key */
      i = key_info;
      switch (lsh_sexp_get_type(&i)) 
	{
	default:
	  werror("Unknown key derivation mechanism.\n");
	  goto fail;

	case ATOM_XPKCS5V2:
	  {
	    const uint8_t *names[2] = { "salt", "iterations" };
	    struct sexp_iterator values[2];
	    
	    CAST_SUBTYPE(mac_algorithm, tmp,
			 spki_algorithm_lookup(mac_algorithms,
					       &i, NULL));

	    mac = tmp;

	    if (! (sexp_iterator_assoc(&i, 2, names, values)
		   && (salt = lsh_sexp_to_string(&values[0], NULL))
		   && sexp_iterator_get_uint32(&values[1], &iterations)
		   && iterations))
	      goto fail;
	  }

	  if (!mac)
	    {
	      werror("Unknown mac for pkcs5v2.\n");
	      goto fail;
	    }

	  /* Do the work */

	  {
	    struct lsh_string *password
	      = INTERACT_READ_PASSWORD(interact, 500,
				       ssh_format("Passphrase for key `%lS': ",
						  label), 1);
	    struct lsh_string *clear;
	    uint8_t *key;
	    
	    if (!password)
	      {
		werror("No password provided for pkcs5v2.");
		goto fail;
	      }

	    key = alloca(crypto->key_size);
	    pkcs5_derive_key(mac,
			     password->length, password->data,
			     salt->length, salt->data,
			     iterations,
			     crypto->key_size, key);
	    
	    clear = crypt_string_unpad(MAKE_DECRYPT(crypto,
						    key,
						    iv ? iv->data : NULL),
				       data, 0);

	    lsh_string_free(data);
	    lsh_string_free(expr);
	    lsh_string_free(iv);
	    lsh_string_free(password);
	    lsh_string_free(salt);
	    	    
	    if (!clear)
	      werror("Bad password for pkcs5v2.\n");

	    return clear;
	  }
	}
    }
}
