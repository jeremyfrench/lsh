/* spki.c
 *
 * An implementation of SPKI certificate checking
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Bal�zs Scheidler, Niels M�ller
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

#include <assert.h>
#include <string.h>

#define GABA_DEFINE
#include "spki.h.x"
#undef GABA_DEFINE

#include "spki.c.x"

#define SA(x) sexp_a(ATOM_##x)

struct exception *
make_spki_exception(UINT32 type, const char *msg, struct sexp *expr)
{
  NEW(spki_exception, self);
  assert(type & EXC_SPKI);

  self->super.type = type;
  self->super.msg = msg;
  self->expr = expr;

  return &self->super;
}

/* FIXME: This should create different tags for hostnames that are not
 * dns fqdn:s. */

struct sexp *
make_ssh_hostkey_tag(struct address_info *host)
{
  UINT32 left = host->ip->length;
  UINT8 *s = host->ip->data;
  
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

  return sexp_l(2, sexp_z("ssh-hostkey"),
		sexp_s(NULL, reversed),
		-1);
}      


struct verifier *
spki_make_verifier(struct alist *algorithms,
		   struct sexp *e)
{
  /* Syntax: (<algorithm> <s-expr>*) */
  struct signature_algorithm *algorithm;
  struct verifier *v;
  int algorithm_name;
  struct sexp_iterator *i;

  algorithm_name = spki_get_type(e, &i);

  {
    CAST_SUBTYPE(signature_algorithm, a, 
		 ALIST_GET(algorithms, algorithm_name));
    algorithm = a;
  }
  
  if (!algorithm)
    {
      werror("spki_make_verifier: Unsupported algorithm %a.\n", algorithm_name);
      return NULL;
    }

  v = MAKE_VERIFIER(algorithm, i);
  KILL(i);
  
  if (!v)
    {
      werror("spki_make_verifier: Invalid public-key data.\n");
      return NULL;
    }
  
  return v;
}

/* FIXME: Merge spki_make_signer and spki_sexp_to_signer? */
/* Returns the algorithm type, or zero on error. */
struct signer *
spki_make_signer(struct alist *algorithms,
		 struct sexp *e,
		 int *type)
{
  /* Syntax: (<algorithm> <s-expr>*) */
  struct signature_algorithm *algorithm;
  struct signer *s;
  int algorithm_name;
  struct sexp_iterator *i;

  algorithm_name = spki_get_type(e, &i);

  if (!algorithm_name)
    return NULL;
  
  {
    CAST_SUBTYPE(signature_algorithm, a, 
		 ALIST_GET(algorithms, algorithm_name));
    algorithm = a;
  }

  if (!algorithm)
    {
      werror("spki_make_signer: Unsupported algorithm %a.\n", algorithm_name);
      return NULL;
    }

  s = MAKE_SIGNER(algorithm, i);
  KILL(i);
  
  if (!s)
    {
      werror("spki_make_signer: Invalid public-key data.\n");
      return NULL;
    }

  if (type)
    *type = algorithm_name;

  return s;
}

/* Reading keys */

struct signer *
spki_sexp_to_signer(struct alist *algorithms,
                    struct sexp *key,
                    int *algorithm_name)
{
  struct sexp_iterator *i;
  
  if ((i = sexp_check_type(key, ATOM_PRIVATE_KEY)))
    {
      struct sexp *expr = SEXP_GET(i);
      struct signer *s;
      
      if (!expr)
        {
          werror("sexp_to_signer: Invalid key\n");
          return NULL;
        }
      
      s = spki_make_signer(algorithms, expr, algorithm_name);
      
      if (s)
	/* Test key here? */
	;
      else
	werror("sexp_to_signer: Invalid key.", expr);

      return s;
    }
  werror("sexp_to_signer: Expected private-key expression.");
  return NULL;
}

struct sexp *
spki_make_public_key(struct verifier *verifier)
{
  return sexp_l(2, SA(PUBLIC_KEY),
		PUBLIC_SPKI_KEY(verifier), -1);
}

/* Returns 0 or an atom */
int
spki_get_type(struct sexp *e, struct sexp_iterator **res)
{
  struct sexp_iterator *i;
  int type;
  
  if (sexp_atomp(e) || sexp_nullp(e))
    return 0;

  i = SEXP_ITER(e);

  type = sexp2atom(SEXP_GET(i));
  if (type && res)
    {
      SEXP_NEXT(i);
      *res = i;
    }
  else
    KILL(i);

  return type;
}

struct sexp *
spki_hash_data(struct hash_algorithm *algorithm,
	       int algorithm_name,
	       UINT32 length, UINT8 *data)
{
  struct hash_instance *hash = MAKE_HASH(algorithm);
  struct lsh_string *out = lsh_string_alloc(hash->hash_size);

  HASH_UPDATE(hash, length, data);
  HASH_DIGEST(hash, out->data);

  return sexp_l(3,
		SA(HASH),
		sexp_a(algorithm_name),
		sexp_s(NULL, out), -1);
}  

/* Create an SPKI hash from an s-expression. */

struct sexp *
spki_hash_sexp(struct hash_algorithm *algorithm,
	       int name,
	       struct sexp *expr)
{
  struct lsh_string *s = hash_string(algorithm,
				     sexp_format(expr, SEXP_CANONICAL, 0),
				     1);
  struct sexp *hash = spki_hash_data(algorithm, name, 
				     s->length, s->data);
  lsh_string_free(s);

  return hash;
}


/* 5-tuples */

struct spki_subject *
make_spki_subject(struct sexp *key,
		  struct verifier *verifier,
		  struct lsh_string *sha1,
		  struct lsh_string *md5)
{
  NEW(spki_subject, self);
  self->key = key;
  self->verifier = verifier;
  self->sha1 = sha1;
  self->md5 = md5;

  return self;
}

static int
subject_match_hash(struct spki_subject *self,
		   int method,
		   const struct lsh_string *h1)
{
  struct lsh_string *h2;

  switch (method)
    {
    case ATOM_SHA1:
      if (self->sha1)
	h2 = self->sha1;
#if 0
      else if (self->key)
	h2 = self->sha1
	  = hash_string(&sha1_algorithm,
			sexp_format(self->key, SEXP_CANONICAL, 0), 1);
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
	  = hash_string(&md5_algorithm,
			sexp_format(self->key, SEXP_CANONICAL, 0), 1);
#endif
      else
	return 0;
      break;

    default:
      return 0;
    }
  return lsh_string_eq(h1, h2);
}

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
       (resource object sexp)))
*/

static int
do_spki_tag_atom_match(struct spki_tag *s,
		       struct sexp *e)
{
  CAST(spki_tag_atom, self, s);

  assert(sexp_atomp(self->resource));
  
  return sexp_atomp(e)
    && sexp_atoms_eq(self->resource, e);
}

static struct spki_tag *
make_spki_tag_atom(struct sexp *resource)
{
  NEW(spki_tag_atom, self);

  assert(sexp_atomp(resource));
  
  self->super.type = SPKI_TAG_ATOM;
  self->super.match = do_spki_tag_atom_match;

  self->resource = resource;

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
		       struct sexp *e)
{
  CAST(spki_tag_list, self, s);
  unsigned i;
  struct sexp_iterator *j;
  
  if (sexp_atomp(e))
    return 0;

  for (i = 0, j = SEXP_ITER(e);
       i<LIST_LENGTH(self->list);
       i++, SEXP_NEXT(j))
    {
      CAST_SUBTYPE(spki_tag, tag, LIST(self->list)[i]);
      struct sexp *o = SEXP_GET(j);

      if (! (o && SPKI_TAG_MATCH(tag, o)))
	return 0;
    }
  
  return 1;
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
		      struct sexp *e)
{
  CAST(spki_tag_set, self, s);
  unsigned i;

  for (i = 0; i<LIST_LENGTH(self->set); i++)
    {
      CAST_SUBTYPE(spki_tag, tag, LIST(self->set)[i]);
      if (SPKI_TAG_MATCH(tag, e))
	return 1;
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
       (prefix object sexp)))
*/

static int
do_spki_tag_prefix_match(struct spki_tag *s,
			 struct sexp *e)
{
  CAST(spki_tag_prefix, self, s);
  const struct lsh_string *ed;
  const struct lsh_string *pd;

  assert(sexp_atomp(self->prefix));
  
  if (!sexp_atomp(e))
    return 0;

  ed = sexp_display(e);
  pd = sexp_display(self->prefix);
  
  return (ed ? (pd && lsh_string_eq(ed, pd)) : !pd)
    && lsh_string_prefixp(sexp_contents(self->prefix),
			  sexp_contents(e));
}

static struct spki_tag *
make_spki_tag_prefix(struct sexp *prefix)
{
  NEW(spki_tag_prefix, self);

  self->super.type = SPKI_TAG_PREFIX;
  self->super.match = do_spki_tag_prefix_match;

  self->prefix = prefix;

  return &self->super;
}


static int
do_spki_tag_any_match(struct spki_tag *self UNUSED,
			 struct sexp *e UNUSED)
{
  return 1;
}

/* FIXME: Make this const */
struct spki_tag spki_tag_any =
{ STATIC_HEADER, SPKI_TAG_ANY, do_spki_tag_any_match };


static struct object_list *
spki_sexp_to_tag_list(struct sexp_iterator *i, unsigned limit)
{
  unsigned left;
  struct object_list *l;
  unsigned j;

  left = SEXP_LEFT(i);

  if (!left)
    {
      werror("spki_sexp_to_tag_list: Empty list.\n");
      return NULL;
    }
  
  l = alloc_object_list(left);
  
  for (j = 0; j<left; j++)
    {
      struct spki_tag *tag = spki_sexp_to_tag(SEXP_GET(i), limit);
      if (!tag)
	{
	  /* FIXME: We could explicitly kill the elements of the list
	   * as well. */
	  KILL(l);
	  return NULL;
	}
      LIST(l)[j] = &tag->super;
      SEXP_NEXT(i);
    }
  assert(!SEXP_GET(i));

  return l;
}

struct spki_tag *
spki_sexp_to_tag(struct sexp *e,
		 /* Some limit on the recursion */
		 unsigned limit)
{
  if (sexp_atomp(e))
    return make_spki_tag_atom(e);
  else
    {
      struct sexp_iterator *i;
      if (!limit)
	{
	  werror("spki_sexp_to_tag: Nesting too deep.\n");
	  return NULL;
	}
      
      if ((i = sexp_check_type(e, ATOM_STAR)))
	{
	  struct sexp *magic = SEXP_GET(i);
	  
	  if (!magic)
	    return &spki_tag_any;

	  SEXP_NEXT(i);
	  
	  switch(sexp2atom(magic))
	    {
	    case ATOM_SET:
	      {
		struct object_list *l = spki_sexp_to_tag_list(i, limit - 1);

		return l ? make_spki_tag_set(l) : NULL;
	      }
	    case ATOM_PREFIX:
	      {
		struct sexp *prefix = SEXP_GET(i);

		return (prefix && sexp_atomp(prefix))
		  ? make_spki_tag_prefix(prefix)
		  : NULL;
	      }
	    default:
	      werror("spki_sexp_to_tag: Invalid (* ...) tag.\n");
	      return NULL;
	    }
	}
      else
	{
	  struct object_list *l = spki_sexp_to_tag_list(SEXP_ITER(e), limit - 1);

	  return l ? make_spki_tag_list(l) : NULL;
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
  struct sexp_iterator *j;
  struct spki_tag *authorization;
  
  int propagate = 0;
  
  struct sexp *e = SEXP_GET(i);
  
  if (!e)
    {
      werror("spki_acl_entry_to_5_tuple: Invalid entry.\n");
      return NULL;
    }

  subject = SPKI_LOOKUP(ctx, e, NULL);
  if (!subject)
    return NULL;

  SEXP_NEXT(i);
  e = SEXP_GET(i);
  if (!e)
    return NULL;

  if ((j = sexp_check_type(e, ATOM_PROPAGATE)))
    {
      if (SEXP_GET(j))
	{
	  werror("spki_acl_entry_to_5_tuple: Invalid propagate-expression.\n");
	  return NULL;
	}
      propagate = 1;
      SEXP_NEXT(i);
      e = SEXP_GET(i);
    }

  if ((j = sexp_check_type(e, ATOM_TAG)))
    {
      struct sexp *tag = SEXP_GET(j);
      SEXP_NEXT(j);
      if (SEXP_GET(j))
	{
	  werror("spki_acl_entry_to_5_tuple: Invalid tag-expression.\n");
	  return NULL;
	}
      
      authorization = spki_sexp_to_tag(tag, SPKI_NESTING_LIMIT);
      if (!authorization)
	return NULL;
    }
  else
    {
      werror("spki_acl_entry_to_5_tuple: Invalid entry.\n");
      return NULL;
    }
    
  SEXP_NEXT(i);
  if (SEXP_GET(i))
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
 * were correct, 0 on any error. However, it tries to go on if some
 * sub-expression is invalid. */

int
spki_add_acl(struct spki_context *ctx,
	     struct sexp *e)
{
  struct sexp_iterator *i;
  int res = 1;
  
  if (!(i = sexp_check_type(e, ATOM_ACL)))
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
  
  for (; (e = SEXP_GET(i)); SEXP_NEXT(i))
    {
      struct sexp_iterator *j;
      if ((j = sexp_check_type(e, ATOM_ENTRY)))
	{
	  struct spki_5_tuple *acl = spki_acl_entry_to_5_tuple(ctx, j);
	  if (acl)
	    SPKI_ADD_TUPLE(ctx, acl);
	  else res = 0;
	}
      else
	{
	  werror("spki_read_acls: Invalid entry, ignoring\n");
	  res = 0;
	}
    }

  return res;
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

static struct spki_subject *
do_spki_lookup(struct spki_context *s,
	       struct sexp *e,
	       struct verifier *v)

{
  CAST(spki_state, self, s);
  struct sexp_iterator *i;

  switch (spki_get_type(e, &i))
    {
    case ATOM_HASH:
      {
	/* Syntax: (hash <hash-alg-name> <hash-value> <uris>) */
	struct spki_subject *subject;
	const struct lsh_string *hash;

	int method = sexp2atom(SEXP_GET(i));
	if (!method)
	  return NULL;

	SEXP_NEXT(i);
	hash = sexp2string(SEXP_GET(i));

	if (!hash)
	  return NULL;

	SEXP_NEXT(i);
	if (SEXP_GET(i))
	  return NULL;
	
	subject = spki_subject_by_hash(self, method, hash);
	
	if (!subject)
	  {
	    switch (method)
	      {
	      case ATOM_SHA1:
		subject = make_spki_subject(NULL, NULL, lsh_string_dup(hash), NULL);
		break;
	      case ATOM_MD5:
		subject = make_spki_subject(NULL, NULL, NULL, lsh_string_dup(hash));
		break;
	      default:
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
	struct lsh_string *sha1;
	struct lsh_string *md5;
	struct sexp *key = SEXP_GET(i);

	if (!key)
	  {
	    werror("do_spki_lookup: Invalid (public-key ...) expression.\n");
	    return NULL;
	  }

	/* We first se if we can find the key by hash */
	{
	  struct lsh_string *canonical = sexp_format(e, SEXP_CANONICAL, 0);
	  sha1 = hash_string(&sha1_algorithm, canonical, 0);
	  md5 = hash_string(&md5_algorithm, canonical, 1);
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
	  {
	    /* New subject */
	    subject = make_spki_subject(e,
					v ? v : spki_make_verifier(self->algorithms, key),
					sha1, md5);
	    
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
		  struct sexp *access)
{
  CAST(spki_state, self, s);

  FOR_OBJECT_QUEUE(&self->db, n)
    {
      CAST(spki_5_tuple, tuple, n);

      /* FIXME: Handles ACL:s only. I.e. issuer == NULL. */
      if ( (user == tuple->subject)
	   && !tuple->issuer
	   && SPKI_TAG_MATCH(tuple->authorization, access))
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

struct sexp *
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
  struct sexp *method;
  
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

  method = sexp_l(4, SA(XPKCS5V2), sexp_a(prf_name),
                  sexp_l(2, SA(ITERATIONS), sexp_uint32(iterations), -1),
                  sexp_l(2, SA(SALT), sexp_s(NULL, salt), -1), -1);

  if (crypto->iv_size)
    {
      iv = lsh_string_alloc(crypto->iv_size);
      RANDOM(r, iv->length, iv->data);
    }
  else
    iv = NULL;

  return sexp_l(4,
                SA(PASSWORD_ENCRYPTED),
                sexp_s(NULL, lsh_string_dup(label)),
                method,
                sexp_l(3,
                       sexp_a(crypto_name),
                       sexp_l(2, SA(IV), sexp_s(NULL, iv), -1),
                       sexp_l(2, SA(DATA),
                              sexp_s(NULL, crypt_string_pad
                                     (MAKE_ENCRYPT(crypto,
                                                   key->data,
                                                   iv ? iv->data : NULL),
                                      data, 0)),
                              -1),
                       -1),
                -1);
}

struct sexp *
spki_pkcs5_decrypt(struct alist *mac_algorithms,
                   struct alist *crypto_algorithms,
                   struct interact *interact,
                   struct sexp *expr)
{
  struct sexp_iterator *i;
  
  if (!(i = sexp_check_type(expr, ATOM_PASSWORD_ENCRYPTED)))
    return expr;

  else
    {
      const struct lsh_string *label;
      struct sexp *key_info;
      struct sexp *payload;

      struct crypto_algorithm *crypto;
      struct mac_algorithm *mac;
      
      const struct lsh_string *salt;
      const struct lsh_string *iv;
      const struct lsh_string *data;
      UINT32 iterations;
      
      if (SEXP_LEFT(i) != 3)
	{
	  werror("Invalid (password-encrypted ...) expression.\n");
	  return NULL;
	}
	
      /* NOTE: This is a place where it might make sense to use a sexp
       * display type, but we don't support that for now. */
      label = sexp2string(SEXP_GET(i));

      if (!label)
	{
	  werror("Invalid label in (password-encrypted ...) expression.\n");
	  return NULL;
	}

      SEXP_NEXT(i);
      key_info = SEXP_GET(i);
      assert(key_info);

      SEXP_NEXT(i);
      payload = SEXP_GET(i);
      assert(payload);

      /* Examine the payload expression first, before asking for a
       * pass phrase. */

      {
	int algorithm_name = spki_get_type(payload, &i);
	CAST_SUBTYPE(crypto_algorithm, tmp,
		     ALIST_GET(crypto_algorithms, algorithm_name));
	crypto = tmp;
      }

      if (!crypto)
	{
          werror("Unknown encryption algorithm for pkcs5v2.\n");
	  return NULL;
	}

      iv = sexp2string(sexp_assq(i, ATOM_IV));

      if (crypto->iv_size)
	{
	  if (!iv || (iv->length != crypto->iv_size))
	    {
	      werror("Invalid IV for pkcs5v2.\n");
	      return NULL;
	    }
	}
      else if (iv)
	{
	  if (iv->length)
	    {
	      werror("Unexpected iv provided for pkcs5v2.\n");
	      return NULL;
	    }
	  iv = NULL;
	}
	
      data = sexp2string(sexp_assq(i, ATOM_DATA));

      if (!data)
	{
	  werror("Payload data missing for pkcs5v2.\n");
	  return NULL;
	}

      if (crypto->block_size && (data->length & crypto->block_size))
	{
	  werror("Payload data doesn't match block size for pkcs5v2.\n");
	  return NULL;
	}

      /* Get key */
      switch (spki_get_type(key_info, &i)) 
	{
	default:
	  werror("Unknown key derivation mechanism.\n");
	  return NULL;

	case ATOM_XPKCS5V2:
	  if (SEXP_LEFT(i) != 3)
	    {
	      werror("Invalid pkcs5v2 parameters.\n");
	      return NULL;
	    }
	  
	  {
	    int algorithm_name = sexp2atom(SEXP_GET(i));
	    
	    CAST_SUBTYPE(mac_algorithm, tmp,
			 ALIST_GET(mac_algorithms,
				   algorithm_name));

	    mac = tmp;
	  }

	  if (!mac)
	    {
	      werror("Unknown mac for pkcs5v2.\n");
	      return NULL;
	    }

	  SEXP_NEXT(i);
	  if (!sexp2uint32(sexp_assq(i, ATOM_ITERATIONS), &iterations)
	      || !iterations)
	    {
	      werror("Invalid iteration count for pkcs5v2.\n");
	      return NULL;
	    }
	    
	  salt = sexp2string(sexp_assq(i, ATOM_SALT));

	  if (!salt)
	    {
	      werror("Invalid salt for pkcs5v2.\n");
	      return NULL;
	    }

	  /* Do the work */

	  {
	    struct lsh_string *password
	      = INTERACT_READ_PASSWORD(interact, 500, label, 0);
	    struct lsh_string *clear;
	    struct sexp *res;
	    UINT8 *key;
	    
	    if (!password)
	      {
		werror("No password provided for pkcs5v2.");
		return NULL;
	      }

	    key = alloca(crypto->key_size);
	    pkcs5_derive_key(mac,
			     password->length, password->data,
			     salt->length, salt->data,
			     iterations,
			     crypto->key_size, key);

	    lsh_string_free(password);

	    clear = crypt_string_unpad(MAKE_DECRYPT(crypto,
						    key,
						    iv ? iv->data : NULL),
				       data, 0);

	    if (!clear)
	      {
		werror("Bad password for pkcs5v2.\n");
		return NULL;
	      }

	    res = string_to_sexp(SEXP_CANONICAL, clear, 1);

	    if (!res)
              werror("Bad password for pkcs5v2.\n");

            return res;
	  }
	}
    }
}
