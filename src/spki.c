/* spki.c
 *
 * An implementation of SPKI certificate checking
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler, Niels Möller
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

#include "nettle/sexp.h"

#include <assert.h>
#include <string.h>

#define GABA_DEFINE
#include "spki.h.x"
#undef GABA_DEFINE

#include "spki.c.x"


/* FIXME: This should create different tags for hostnames that are not
 * dns fqdn:s. */

struct lsh_string *
make_ssh_hostkey_tag(struct address_info *host)
{
  UINT32 left = host->ip->length;
  UINT8 *s = host->ip->data;
  struct lsh_string *tag;
  struct lsh_string *reversed = lsh_string_alloc(left);

  /* First, transform "foo.lysator.liu.se" into "se.liu.lysator.foo" */
  while (left)
    {
      UINT8 *p = memchr(s, '.', left);
      if (!p)
	{
	  memcpy(reversed->data, s, left);
	  break;
	}
      else
	{
	  UINT32 segment = p - s;
	  left -= segment;

	  memcpy(reversed->data + left, s, segment);
	  reversed->data[--left] = '.';
	  s = p+1;
	}
    }

  tag = lsh_sexp_format(0, "(%z%s)",
			"ssh-hostkey", reversed->length, reversed->data);
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
  UINT8 *decoded;  

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
	       UINT32 length, UINT8 *data)
{
  struct hash_instance *hash = make_hash(algorithm);
  UINT8 *out = alloca(HASH_SIZE(hash));

  hash_update(hash, length, data);
  hash_digest(hash, out);

  return lsh_sexp_format(0, "(%z%z%s)",
			 "hash", get_atom_name(algorithm_name),
			 HASH_SIZE(hash), out);
}  


/* 5-tuples */

struct spki_subject *
make_spki_subject(struct sexp_iterator *i,
		  struct verifier *verifier,
		  const struct lsh_string *sha1,
		  const struct lsh_string *md5)
{
  NEW(spki_subject, self);
  self->key = lsh_sexp_copy(i);
  self->verifier = verifier;
  self->sha1 = sha1;
  self->md5 = md5;

  return self;
}

#if 0
static int
subject_match_hash(struct spki_subject *self,
		   int method,
		   const struct lsh_string *h1)
{
  const struct lsh_string *h2;

  switch (method)
    {
    case ATOM_SHA1:
      if (self->sha1)
	h2 = self->sha1;
#if 0
      else if (self->key)
	h2 = self->sha1
	  = hash_string(&sha1_algorithm, self->key, 0);
#endif
      else
	return 0;
      break;

    case ATOM_MD5:
      if (self->md5)
	h2 = self->md5;
#if 0
      else if (self->key)
	h2 = self->md5
	  = hash_string(&md5_algorithm, self->key, 0);
#endif
      else
	return 0;
      break;

    default:
      return 0;
    }
  return lsh_string_eq(h1, h2);
}
#endif

struct spki_5_tuple *
make_spki_5_tuple(struct spki_subject *issuer,
		  struct spki_subject *subject,
		  int propagate,
		  struct spki_tag *authorization,
		  int before_limit, time_t not_before,
		  int after_limit, time_t not_after)
{
  NEW(spki_5_tuple, self);
  self->issuer = issuer;
  self->subject = subject;
  self->propagate = propagate;
  self->authorization = authorization;
  self->validity.before_limit = before_limit;
  self->validity.not_before = not_before;
  self->validity.after_limit = after_limit;
  self->validity.not_after = not_after;

  return self;
}


/* Sets of authorizations, representing the (tag ...) expressions in
 * acl:s and certificates. */

/* An authorization represented as a string (optionally with display
 * type). */

/* GABA:
   (class
     (name spki_tag_atom)
     (super spki_tag)
     (vars
       (display string)
       (resource string)))
*/

static int
do_spki_tag_atom_match(struct spki_tag *s,
		       struct sexp_iterator *e)
{
  CAST(spki_tag_atom, self, s);

  if (e->type != SEXP_ATOM
      || !lsh_string_eq_l(self->resource, e->atom_length, e->atom))
    return 0;
  
  if (self->display)
    {
      if (! (e->display &&
	     lsh_string_eq_l(self->display, e->display_length, e->display)))
	return 0;
    }
  else if (e->display)
    return 0;
  
  return sexp_iterator_next(e);
}

static struct spki_tag *
make_spki_tag_atom(struct sexp_iterator *i)
{
  NEW(spki_tag_atom, self);

  assert(i->type == SEXP_ATOM);
  
  self->super.type = SPKI_TAG_ATOM;
  self->super.match = do_spki_tag_atom_match;

  self->resource = lsh_sexp_to_string(i, &self->display);

  if (!self->resource)
    {
      KILL(self);
      return NULL;
    }
  
  return &self->super;
}


/* An authorization represented as a list. Includes all authorizations
 * that for which a prefix matches the list. */

/* GABA:
   (class
     (name spki_tag_list)
     (super spki_tag)
     (vars
       (list object object_list)))
*/

static int
do_spki_tag_list_match(struct spki_tag *s,
		       struct sexp_iterator *j)
{
  CAST(spki_tag_list, self, s);
  unsigned i;
  
  if (!sexp_iterator_enter_list(j))
    return 0;

  for (i = 0;
       i<LIST_LENGTH(self->list);
       i++)
    {
      CAST_SUBTYPE(spki_tag, tag, LIST(self->list)[i]);

      if (j->type == SEXP_END
	  || !SPKI_TAG_MATCH(tag, j))
	return 0;
    }
  return sexp_iterator_exit_list(j);
}

static struct spki_tag *
make_spki_tag_list(struct object_list *list)
{
  NEW(spki_tag_list, self);

  self->super.type = SPKI_TAG_LIST;
  self->super.match = do_spki_tag_list_match;

  self->list = list;

  return &self->super;
}

/* A (* set ...) construction */

/* GABA:
   (class
     (name spki_tag_set)
     (super spki_tag)
     (vars
       (set object object_list)))
*/

static int
do_spki_tag_set_match(struct spki_tag *s,
		      struct sexp_iterator *e)
{
  CAST(spki_tag_set, self, s);
  unsigned i;

  for (i = 0; i<LIST_LENGTH(self->set); i++)
    {
      struct sexp_iterator j = *e;
      CAST_SUBTYPE(spki_tag, tag, LIST(self->set)[i]);

      if (SPKI_TAG_MATCH(tag, &j))
	{
	  *e = j;
	  return 1;
	}
    }

  return 0;
}

static struct spki_tag *
make_spki_tag_set(struct object_list *set)
{
  NEW(spki_tag_set, self);

  self->super.type = SPKI_TAG_SET;
  self->super.match = do_spki_tag_set_match;

  self->set = set;

  return &self->super;
}

/* Authorizations represented as a string prefix. If display types are
 * present, they must be equal. */

/* GABA:
   (class
     (name spki_tag_prefix)
     (super spki_tag)
     (vars
       (display string)
       (prefix string)))
*/

static int
do_spki_tag_prefix_match(struct spki_tag *s,
			 struct sexp_iterator *i)
{
  CAST(spki_tag_prefix, self, s);
  
  if (i->type != SEXP_ATOM)
    return 0;

  if (self->display)
    {
      if (!i->display
	  || !lsh_string_eq_l(self->display, i->display_length, i->display))
	return 0;
    }
  else if (i->display)
    return 0;
	  
  return i->atom_length >= self->prefix->length
    && !memcmp(i->atom, self->prefix->data, self->prefix->length);
}

static struct spki_tag *
make_spki_tag_prefix(struct sexp_iterator *i)
{
  NEW(spki_tag_prefix, self);

  assert(i->type == SEXP_ATOM);
  
  self->super.type = SPKI_TAG_PREFIX;
  self->super.match = do_spki_tag_prefix_match;

  self->prefix = lsh_sexp_to_string(i, &self->display);
  if (!self->prefix)
    {
      KILL(self);
      return NULL;
    }
  return &self->super;
}


static int
do_spki_tag_any_match(struct spki_tag *self UNUSED,
		      struct sexp_iterator *i)
{
  return sexp_iterator_next(i);
}

/* FIXME: Make this const */
struct spki_tag spki_tag_any =
{ STATIC_HEADER, SPKI_TAG_ANY, do_spki_tag_any_match };


static struct object_list *
spki_sexp_to_tag_list(struct sexp_iterator *i, unsigned limit)
{
  struct object_queue q;

  if (i->type == SEXP_END)
    {
      werror("spki_sexp_to_tag_list: Empty list.\n");
      return NULL;
    }

  object_queue_init(&q);
  
  while (i->type != SEXP_END)
    {
      struct spki_tag *tag = spki_sexp_to_tag(i, limit);
      if (!tag)
	{
	  /* FIXME: We could explicitly kill the elements of the queue
	   * as well. */
	  object_queue_kill(&q);
	  return NULL;
	}
      object_queue_add_tail(&q, &tag->super);
    }

  return queue_to_list_and_kill(&q);
}

struct spki_tag *
spki_sexp_to_tag(struct sexp_iterator *i,
		 /* Some limit on the recursion */
		 unsigned limit)
{
  switch (i->type)
    {
    default:
      abort();
    case SEXP_ATOM:
      return make_spki_tag_atom(i);
    case SEXP_END:
      /* Should this ever happen? */
      abort();
    case SEXP_LIST:
      {
	if (!limit)
	  {
	    werror("spki_sexp_to_tag: Nesting too deep.\n");
	    return NULL;
	  }

	if (!sexp_iterator_enter_list(i))
	  return NULL;

	if (i->type == SEXP_ATOM && !i->display
	    && i->atom_length == 1 && i->atom[0] == '*')
	  {
	    if (!sexp_iterator_next(i))
	      return NULL;

	    if (i->type != SEXP_ATOM || i->display)
	      {
		werror("spki_sexp_to_tag: Invalid (* ...) tag.\n");
		return NULL;
	      }
	    
	    switch (lsh_sexp_to_atom(i))
	      {
	      case ATOM_SET:
		{
		  struct object_list *l = spki_sexp_to_tag_list(i, limit - 1);

		  return l ? make_spki_tag_set(l) : NULL;
		}
	      case ATOM_PREFIX:
		return make_spki_tag_prefix(i);

	      default:
		werror("spki_sexp_to_tag: Invalid (* ...) tag.\n");
		return NULL;
	      }
	  }
	else
	  {
	    struct object_list *l = spki_sexp_to_tag_list(i, limit - 1);
	    
	    return l ? make_spki_tag_list(l) : NULL;
	  }
      }
    }
}

#define SPKI_NESTING_LIMIT 17

/* The iterator should point at the element after the tag of an expression
 *
 *   (entry (public-key|hash|name ...) (propagate)? (tag ...) (valid ...)? )
 */

struct spki_5_tuple *
spki_acl_entry_to_5_tuple(struct spki_context *ctx,
			  struct sexp_iterator *i)
{
  struct spki_subject *subject;
  struct spki_tag *authorization;
  int propagate = 0;
  int type;
  
  subject = SPKI_LOOKUP(ctx, i, NULL);
  if (!subject)
    return NULL;

  type = lsh_sexp_get_type(i);
  if (type == ATOM_PROPAGATE)
    {
      propagate = 1;

      if (!sexp_iterator_enter_list(i))
	return 0;
      type = lsh_sexp_get_type(i);
    }

  if (type != ATOM_TAG)
    {
      werror("spki_acl_entry_to_5_tuple: Invalid entry.\n");
      return NULL;
    }
  else
    {
      authorization = spki_sexp_to_tag(i, SPKI_NESTING_LIMIT);
      if (!authorization || !sexp_iterator_exit_list(i))
	return NULL;
    }

  if (i->type != SEXP_END || !sexp_iterator_exit_list(i))
    {
      werror("spki_acl_entry_to_5_tuple: Garbage at end of entry.\n");
      return NULL;
    }

  /* Create a 5-tuple with a NULL (i.e. self) issuer */
  return make_spki_5_tuple(NULL, subject, propagate,
			   authorization, 0, 0, 0, 0);
}

/* Takes an spki_context and an ACL s-expression, and adds
 * corresponding 5-tuples to the context. Returns 1 if all entries
 * were correct, 0 on any error. */

int
spki_add_acl(struct spki_context *ctx,
	     struct sexp_iterator *i)
{
  if (!sexp_iterator_check_type(i, "acl"))
    {
      werror("spki_read_acls: Invalid acl\n");
      return 0;
    }

  /* FIXME: Accept at least (version "0") */
#if 0
  if (sexp_check_type(SEXP_GET(i), ATOM_VERSION, NULL))
    {
      werror("spki_read_acls: Unsupported acl version\n");
      return 0;
    }
#endif
  
  while (i->type != SEXP_END)
    {
      struct spki_5_tuple *acl;
      if (!sexp_iterator_check_type(i, "entry"))
	return 0;
      
      acl = spki_acl_entry_to_5_tuple(ctx, i);
      if (!acl)
	return 0;
      
      SPKI_ADD_TUPLE(ctx, acl);
    }

  return sexp_iterator_exit_list(i);
}


/* SPKI context */

/* GABA:
   (class
     (name spki_state)
     (super spki_context)
     (vars
       ; Signature algorithms
       (algorithms object alist)
       ;; FIXME: Could have a alist of hash algorithms as well.
       
       ; We could use some kind of hash table instead
       (keys struct object_queue)

       ; Five tuples. 
       (db struct object_queue)))
*/

#if 0
static struct spki_subject *
spki_subject_by_hash(struct spki_state *self,
		     int algorithm,
		     const struct lsh_string *hash)
{
  FOR_OBJECT_QUEUE(&self->keys, n)
    {
      CAST(spki_subject, subject, n);
	    
      if (subject_match_hash(subject, algorithm, hash))
	return subject;
    }
  return NULL;
}
#endif

static struct spki_subject *
do_spki_lookup(struct spki_context *s,
	       struct sexp_iterator *i,
	       struct verifier *v)

{
  CAST(spki_state, self, s);
  
  switch (lsh_sexp_get_type(i))
    {
    case ATOM_HASH:
      {
	/* Syntax: (hash <hash-alg-name> <hash-value> <uris>) */
	struct spki_subject *subject;
	const struct lsh_string *hash;

	int method = lsh_sexp_to_atom(i);
	if (!method)
	  return NULL;

	hash = lsh_sexp_to_string(i, NULL);

	if (!hash)
	  return NULL;

	if (i->type != SEXP_END
	    || !sexp_iterator_exit_list(i))
	  return NULL;

#if 0
	subject = spki_subject_by_hash(self, method, hash);
	
	if (subject)
	  lsh_string_free(hash);
	else
#endif
	  {
	    switch (method)
	      {
	      case ATOM_SHA1:
		subject = make_spki_subject(NULL, NULL, hash, NULL);
		break;
	      case ATOM_MD5:
		subject = make_spki_subject(NULL, NULL, NULL, hash);
		break;
	      default:
		lsh_string_free(hash);
		return NULL;
	      }
	    
	    object_queue_add_tail(&self->keys, &subject->super);
	  }

	if (!subject->verifier && v)
	  subject->verifier = v;

	return subject;
      }
    case ATOM_PUBLIC_KEY:
      {
	/* Syntax: (public-key (<pub-sig-alg-id> <s-expr>*) <uris>) */
	struct spki_subject *subject;
	const struct lsh_string *sha1;
	const struct lsh_string *md5;

	/* FIXME: We should hash the full expression, including
	 * "public-key", uri:s, and any other stuff. */
#if 0
	/* We first se if we can find the key by hash */
	{
	  struct lsh_string *canonical = sexp_format(e, SEXP_CANONICAL, 0);
	  sha1 = hash_string(&crypto_sha1_algorithm, canonical, 0);
	  md5 = hash_string(&crypto_md5_algorithm, canonical, 1);
	}

	if ( ((subject = spki_subject_by_hash(self, ATOM_SHA1, sha1)))
	     || ((subject = spki_subject_by_hash(self, ATOM_MD5, md5))) )
	  {
	    lsh_string_free(md5);
	    lsh_string_free(sha1);

	    if (!subject->key)
	      {
		assert(!subject->verifier);
		subject->key = e;

		subject->verifier
		  = v ? v : spki_make_verifier(self->algorithms, key);
	      }
	  }
	else
#endif
	  {
	    /* New subject */
	    if (!v)
	      {
		v = spki_make_verifier(self->algorithms, i);
		if (!v)
		  return NULL;
	      }
	    /* FIXME: Add sha1 and md5 hashes. */
	    subject = make_spki_subject(i, v, NULL, NULL);
	    
	    object_queue_add_head(&self->keys, &subject->super);
	  }
	
	return subject;
      }
    case ATOM_SEQUENCE:
      werror("do_spki_lookup: spki sequences not yet supported.\n");
      return NULL;
      
    case ATOM_NAME:
      werror("do_spki_lookup: names not yet supported.\n");
      return NULL;
    default:
      werror("do_spki_lookup: Invalid expression.\n");
      return NULL;
    }
}

static void
do_spki_add_tuple(struct spki_context *s,
		  struct spki_5_tuple *tuple)
{
  CAST(spki_state, self, s);

  object_queue_add_tail(&self->db, &tuple->super);
}

static int
do_spki_authorize(struct spki_context *s,
		  struct spki_subject *user,
		  const struct lsh_string *access)
{
  CAST(spki_state, self, s);

  struct sexp_iterator start;

  if (!sexp_iterator_first(&start, access->length, access->data))
    return 0;
  
  FOR_OBJECT_QUEUE(&self->db, n)
    {
      CAST(spki_5_tuple, tuple, n);
      struct sexp_iterator i = start;
      
      /* FIXME: Handles ACL:s only. I.e. issuer == NULL. */
      if ( (user == tuple->subject)
	   && !tuple->issuer
	   && SPKI_TAG_MATCH(tuple->authorization, &i))
	return 1;
    }
  return 0;
}

struct spki_context *
make_spki_context(struct alist *algorithms)
{
  NEW(spki_state, self);
  self->super.lookup = do_spki_lookup;
  self->super.add_tuple = do_spki_add_tuple;
  self->super.authorize = do_spki_authorize;
  
  self->algorithms = algorithms;
  object_queue_init(&self->keys);
  object_queue_init(&self->db);

  return &self->super;
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
		   UINT32 prf_name,
		   struct mac_algorithm *prf,
		   int crypto_name,
		   struct crypto_algorithm *crypto,
		   UINT32 salt_length,
		   struct lsh_string *password,
		   UINT32 iterations,
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
  value = lsh_sexp_format(0, "(%z%s(%z%z(%z%i)(%z%s))(%z(%z%s)(%z%s)))",
			  "password-encrypted", label->length, label->data,
			  "xpkcs5v2", get_atom_name(prf_name),
			  "iterations", iterations,
			  "salt", salt->length, salt->data,
			  get_atom_name(crypto_name),
			  "iv", iv->length, iv->data,
			  "data", encrypted->length, encrypted->data);

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
	 && sexp_iterator_check_type(&i, "password_encrypted")))
    return expr;

  else
    {
      const struct lsh_string *label;
      struct sexp_iterator key_info;

      struct crypto_algorithm *crypto;
      struct mac_algorithm *mac;

      /* FIXME: Leaks some strings. */
      const struct lsh_string *salt = NULL;
      const struct lsh_string *iv = NULL;
      const struct lsh_string *data = NULL;
      UINT32 iterations;
      
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
		   && lsh_sexp_to_uint32(&values[1], &iterations)
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
	    UINT8 *key;
	    
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
