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
#include "list.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"
#include "alist.h"

#include <assert.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

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

#define SPKI_ERROR(e, msg, expr) \
EXCEPTION_RAISE((e), make_spki_exception(EXC_SPKI_TYPE, (msg), (expr)))

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
		make_sexp_string(NULL, reversed),
		-1);
}      
  
struct sexp *
dsa_to_spki_public_key(struct dsa_public *dsa)
{
  return sexp_l(2, SA(PUBLIC_KEY),
		sexp_l(5, SA(DSA),
		       /* FIXME: Should we use unsigned format? */
		       sexp_l(2, SA(P), sexp_un(dsa->p), -1),
		       sexp_l(2, SA(Q), sexp_un(dsa->q), -1),
		       sexp_l(2, SA(G), sexp_un(dsa->g), -1),
		       sexp_l(2, SA(Y), sexp_un(dsa->y), -1),
		       -1),
		-1);
}

#if 0
/* This functions expects only keyblobs of type ssh-dss. When we
 * accept spki keys, we must not accept ssh-dss keys, and vice versa.
 */
struct sexp *keyblob2spki(struct lsh_string *keyblob)
{
  struct simple_buffer buffer;
  UINT32 kbtype;
  struct sexp *e = NULL;
  
  simple_buffer_init(&buffer, keyblob->length, keyblob->data);

  if (parse_atom(&buffer, &kbtype))
    switch(kbtype)
      {
      case ATOM_SSH_DSS:
	{
	  struct dsa_public dsa;
	  init_dsa_public(&dsa);
      
	  if (parse_dsa_public(&buffer, &dsa)
	      && parse_eod(&buffer))
	    e = sexp_l(2, SA(PUBLIC_KEY),
		       sexp_l(5, SA(DSA),
			      /* FIXME: Should we use unsigned format? */
			      sexp_l(2, SA(P), sexp_un(dsa.p), -1),
			      sexp_l(2, SA(Q), sexp_un(dsa.q), -1),
			      sexp_l(2, SA(G), sexp_un(dsa.g), -1),
			      sexp_l(2, SA(Y), sexp_un(dsa.y), -1),
			      -1),
		       -1);
	  else
	    werror("Invalid dsa keyblob.");
      
	  dsa_public_free(&dsa);
	  break;
	}
#if 0
      case ATOM_SPKI:
	e = sexp_parse_canonical(&buffer);
	if (! (e && parse_eod(&buffer)))
	  {
	    werror("Invalid spki keyblob\n");
	    e = NULL;
	  }
	break;
#endif
      default:
	werror("Unknown keyblob format, only ssh-dss is supported\n");
      }
  else
    werror("Invalid keyblob.\n");

  return e;
}
#endif

/* Returns 0 or an atom */
int spki_get_type(struct sexp *e, struct sexp_iterator **res)
{
  struct sexp_iterator *i;
  UINT32 type;
  
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

/* Returns 1 if the type matches. */
int
spki_check_type(struct sexp *e, int type, struct sexp_iterator **res)
{
  struct sexp_iterator *i =
    sexp_check_type(e, get_atom_length(type), get_atom_name(type));

  if (i)
    {
      if (res)
	*res = i;
      else
	KILL(i);
      return 1;
    }
  return 0;
}

#if 0
/* NOTE: This function requires a particular order. */
static struct sexp *dsa_private2public(struct sexp_iterator *i)
{
  struct sexp *p;
  struct sexp *q;
  struct sexp *g;
  struct sexp *y;
  struct sexp *x;

  /* FIXME: Check length? */
  if ( (p = sexp_assq(i, ATOM_P))
       && (q = sexp_assq(i, ATOM_Q))
       && (g = sexp_assq(i, ATOM_G))
       && (y = sexp_assq(i, ATOM_Y))
       && (x = sexp_assq(i, ATOM_X)))
    return sexp_l(2, SA(PUBLIC_KEY),
		  sexp_l(5, SA(DSA), p, q, g, y, -1), -1);
  else
    return NULL;
      
}


static void
do_spki_private2public(struct command *s UNUSED,
		       struct lsh_object *a,
		       struct command_continuation *c,
		       struct exception_handler *e)
{
  CAST_SUBTYPE(sexp, key, a);
  struct sexp_iterator *i;
  struct sexp *expr;
  struct sexp *pub;

  if (!spki_check_type(key, ATOM_PRIVATE_KEY, &i))
    {
      SPKI_ERROR(e, "spki.c: Expected private key.", key);
      return;
    }

  expr = SEXP_GET(i);
  KILL(i);
  switch (spki_get_type(expr, &i))
    {
    default:
      SPKI_ERROR(e, "spki.c: Unknown key type (only dsa is supported).", key);
      break;
    case ATOM_DSA:
      {
	pub = dsa_private2public(i);
	if (!pub)
	  {
	    SPKI_ERROR(e, "spki.c: Invalid DSA key.", key);
	  }
	else
	  COMMAND_RETURN(c, pub);	
      }
    }
}

struct command spki_private2public
= STATIC_COMMAND(do_spki_private2public);
#endif

COMMAND_SIMPLE(spki_signer2public)
{
  CAST_SUBTYPE(signer, private, a);
  return &SIGNER_PUBLIC(private)->super;
}

/* Create an SPKI hash from an s-expression. */
/* GABA:
   (class
     (name spki_hash)
     (super command)
     (vars
       (name . int)
       (algorithm object hash_algorithm)))
*/

static void do_spki_hash(struct command *s,
			 struct lsh_object *a,
			 struct command_continuation *c,
			 struct exception_handler *e UNUSED)
{
  CAST(spki_hash, self, s);
  CAST_SUBTYPE(sexp, o, a);

  COMMAND_RETURN(c, sexp_l(3,
			   SA(HASH),
			   sexp_a(self->name),
			   make_sexp_string(NULL,
					    hash_string(self->algorithm,
							sexp_format(o, SEXP_CANONICAL, 0),
							1)),
			   -1));
}

struct command *
make_spki_hash(int name, struct hash_algorithm *algorithm)
{
  NEW(spki_hash, self);
  self->super.call = do_spki_hash;
  self->name = name;
  self->algorithm = algorithm;

  return &self->super;
}

const struct spki_hash spki_hash_md5 =
{ STATIC_COMMAND(do_spki_hash), ATOM_MD5, &md5_algorithm };

const struct spki_hash spki_hash_sha1 =
{ STATIC_COMMAND(do_spki_hash), ATOM_SHA1, &sha1_algorithm };


  
/* Used for both sexp2keypair and sexp2signer.
 *
 * FIXME: There is some overlap between those two functions. */

/* GABA:
   (class
     (name spki_parse_key)
     (super command)
     (vars
       (algorithms object alist)))
*/

#if 0
/* FIXME: Perhaps this function should throw exceptions? */
static struct keypair *
parse_dsa_private_key(struct sexp_iterator *i
		      /*, struct exception_handler *e */)
{
  struct dsa_signer *key = make_dsa_spki_signer(i, random);

  if (key)
    {
      /* Test key */
      mpz_t tmp;
      int valid;
      
      mpz_init_set(tmp, key->public.g);
      mpz_powm(tmp, tmp, key->a, key->public.p);
      valid = !mpz_cmp(tmp, key->public.y);
      mpz_clear(tmp);      

      if (valid)
	{
	  struct lsh_string *public
	    = ssh_format("%a%n%n%n%n", ATOM_SSH_DSS,
			 key->public.p, key->public.q,
			 key->public.g, key->public.y);

	  debug("spki.c: parse_dsa_private_key: Using (public) key:\n"
		"  p=%xn\n"
		"  q=%xn\n"
		"  g=%xn\n"
		"  y=%xn\n",
		key->public.p, key->public.q,
		key->public.g, key->public.y);
	  
	  return make_keypair(ATOM_SSH_DSS, public, &key->super);
	}
      else
	werror("spki.c: parse_dsa_private_key: Key doesn't work.");
    }

  return NULL;
}
#endif

static void
do_spki_sexp2signer(struct command *s, 
		    struct lsh_object *a,
		    struct command_continuation *c,
		    struct exception_handler *e)
{
  CAST(spki_parse_key, self, s);
  CAST_SUBTYPE(sexp, key, a);
  
  struct sexp_iterator *i;
  
  if (spki_check_type(key, ATOM_PRIVATE_KEY, &i)) 
    {
      struct sexp *expr = SEXP_GET(i);
      struct sexp_iterator *inner;
      int type = spki_get_type(expr, &inner);

      CAST_SUBTYPE(signature_algorithm, algorithm,
		   ALIST_GET(self->algorithms, type));

      if (algorithm)
	{
	  struct signer *s = MAKE_SIGNER(algorithm, inner);
	  if (s)
	    /* Test key here? */
	    COMMAND_RETURN(c, s);
	  else
	    {
	      werror("parse_private_key: Invalid key.\n");
	      SPKI_ERROR(e, "spki.c: Invalid key.", expr); 
	    }
	}
    }
  else
    SPKI_ERROR(e, "spki.c: Expected private-key expression.", key);
}

/* (parse algorithms sexp) -> signer */
COMMAND_SIMPLE(spki_sexp2signer_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  NEW(spki_parse_key, self);
  
  self->super.call = do_spki_sexp2signer;
  self->algorithms = algorithms;
  return &self->super.super;
}


static void 
parse_private_key(struct alist *algorithms,
                  struct sexp_iterator *i,
		  struct command_continuation *c,
		  struct exception_handler *e)
{
  struct sexp *expr = SEXP_GET(i);
  struct sexp_iterator *inner;
  int type = spki_get_type(expr, &inner);

  CAST_SUBTYPE(signature_algorithm, algorithm,
	       ALIST_GET(algorithms, type));

  if (algorithm)
    {
      struct signer *s = MAKE_SIGNER(algorithm, inner);
      if (!s)
	{
	  werror("parse_private_key: Invalid key.\n");
	  SPKI_ERROR(e, "spki.c: Invalid key.", expr); 
	  return;
	}
      /* Test key here? */
      switch (type)
	{
	case ATOM_DSA:
	  COMMAND_RETURN(c, make_keypair(ATOM_SSH_DSS,
					 ssh_dss_public_key(s),
					 s));
	  /* Fall through */
	default:
	  /* Get a corresponding public key. */
	  COMMAND_RETURN(c, make_keypair(ATOM_SPKI,
					 sexp_format(SIGNER_PUBLIC(s), SEXP_CANONICAL, 0),
					 s));

	  break;
	}
    }
  else
    {
      werror("spki.c: Unknown key type (only dsa is supported).");
      SPKI_ERROR(e, "spki.c: Unknown key type (only dsa is supported).", expr);
    }
}

static void
do_spki_sexp2keypair(struct command *s, 
		     struct lsh_object *a,
		     struct command_continuation *c,
		     struct exception_handler *e)
{
  CAST(spki_parse_key, self, s);
  CAST_SUBTYPE(sexp, key, a);
  
  struct sexp_iterator *i;
  
  switch (spki_get_type(key, &i)) 
    {
      default:
        SPKI_ERROR(e, "spki.c: Expected private-key expression.", key);
        return;
      case ATOM_PRIVATE_KEY:
	{
	  parse_private_key(self->algorithms, i, c, e);
	  break;
	}
#if 0
      case ATOM_PUBLIC_KEY:
        break;
#endif
    } 
}

#if 0
struct command *
make_spki_parse_key(struct alist *algorithms)
{
  NEW(spki_parse_key, self);
  
  self->super.call = do_spki_parse_key;
  self->algorithms = algorithms;
  return &self->super;
}
#endif

/* (parse algorithms sexp) -> one or more keypairs */
COMMAND_SIMPLE(spki_sexp2keypair_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  NEW(spki_parse_key, self);
  
  self->super.call = do_spki_sexp2keypair;
  self->algorithms = algorithms;
  return &self->super.super;
}
  
#if 0
/* ;; GABA:
   (class
     (name handle_key)
     (super command_continuation)
     (vars
       (key simple "struct keypair **")))
*/

static void
do_handle_key(struct command_continuation *c, struct lsh_object *r)
{
  CAST(handle_key, self, c);
  CAST(keypair, key, r);

  *self->key = key;
}

/* FIXME: We should really use some command instead. */
/* NOTE: Reads only the first key from the file. */
struct keypair *
read_spki_key_file(const char *name,
		   struct alist *algorithms,
		   struct exception_handler *e)
{
  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      EXCEPTION_RAISE(e, make_io_exception(EXC_IO_OPEN_READ, NULL, errno, NULL));
    }
  else
    {
      struct keypair *keypair = NULL;
      int res;

      NEW(handle_key, handler);
      handler->super.c = do_handle_key;
      handler->key = &keypair;

      e = make_report_exception_handler(EXC_SEXP, EXC_SEXP, "Reading keyfile: ",
					e, HANDLER_CONTEXT);
					
      res = blocking_read(fd,
			  make_read_sexp(SEXP_TRANSPORT, 0,
					 make_apply(make_spki_parse_key(algorithms), 
					            &handler->super, 
					            e), 
					 e));
      close(fd);
      KILL(handler);

      return keypair;
    }
  return NULL;
}
#endif

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
		   struct lsh_string *h1)
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
    && sexp_atom_eq(self->resource, e);
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
  struct lsh_string *ed;
  struct lsh_string *pd;

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
      
      if (spki_check_type(e, ATOM_STAR, &i))
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

  if (spki_check_type(e, ATOM_PROPAGATE, &j))
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

  if (spki_check_type(e, ATOM_TAG, &j))
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

/* A command that takes an spki_context and an ACL s-expression, and
 * adds corresponding 5-tuples to the context. Returns 1 if all
 * entries were correct, 0 on any error. However, it tries to gon on
 * if some sub-expression is invalid. */

int
spki_add_acl(struct spki_context *ctx,
	     struct sexp *e)
{
  struct sexp_iterator *i;
  int res = 1;
  
#if 0
  struct object_queue q;
#endif
  if (!spki_check_type(e, ATOM_ACL, &i))
    {
      werror("spki_read_acls: Invalid acl\n");
      return 0;
    }

  /* FIXME: Accept at least (version "0") */
  if (spki_check_type(SEXP_GET(i), ATOM_VERSION, NULL))
    {
      werror("spki_read_acls: Unsupported acl version\n");
      return 0;
    }
#if 0
  object_queue_init(&q);
#endif
  
  for (; (e = SEXP_GET(i)); SEXP_NEXT(i))
    {
      struct sexp_iterator *j;
      if (spki_check_type(e, ATOM_ENTRY, &j))
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
		     int algorithm, struct lsh_string *hash)
{
  FOR_OBJECT_QUEUE(&self->keys, n)
    {
      CAST(spki_subject, subject, n);
	    
      if (subject_match_hash(subject, algorithm, hash))
	return subject;
    }
  return NULL;
}

static struct verifier *
spki_make_verifier(struct alist *algorithms,
		   struct sexp *e)
{
  /* Syntax: (<algorithm> <s-expr>*) */
  struct signature_algorithm *algorithm;
  struct verifier *v;
  int algorithm_name;
  struct sexp_iterator *i;

  algorithm_name = spki_get_type(e, &i);
  
  algorithm = ALIST_GET(algorithms, algorithm_name);

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
	struct lsh_string *hash;

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

#if 0
static void
do_read_acls(struct command *s, 
	     struct lsh_object *a,
	     struct command_continuation *c,
	     struct exception_handler *e)
{
  CAST(spki_command, self, s);
  CAST_SUBTYPE(sexp, acl, a);

  struct object_list *l = spki_read_acls(self->ctx, acl);

  if (l)
    COMMAND_RETURN(c, l);
  else
    SPKI_ERROR(e, "Invalid ACL list", acl);
}
#endif

#if 0

struct signer *
spki_signer(struct sexp *e, struct alist *algorithms, int *t)
{
  struct sexp_iterator *i;
  
  if (spki_check_type(e, ATOM_PRIVATE_KEY, &i))
    {
      struct sexp *key = SEXP_GET(i);
      struct sexp_iterator *inner;
      int type = spki_get_type(key, &inner);
      
      if (type)
	{
	  CAST_SUBTYPE(spki_algorithm, algorithm, ALIST_GET(algorithms, type));

	  if (algorithm)
	    {
	      *t = type;
	      return SPKI_SIGNER(algorithm, i);
	    }
	}
    }
  return NULL;
}

struct verifier *
spki_verifier(struct sexp *e, struct alist *algorithms, int *t)
{
  struct sexp_iterator *i;
  
  if (spki_check_type(e, ATOM_PRIVATE_KEY, &i))
    {
      struct sexp *key = SEXP_GET(i);
      struct sexp_iterator *inner;
      int type = spki_get_type(key, &inner);
      
      if (type)
	{
	  CAST_SUBTYPE(spki_algorithm, algorithm, ALIST_GET(algorithms, type));

	  if (algorithm)
	    {
	      *t = type;
	      return SPKI_VERIFIER(algorithm, i);
	    }
	}
    }
  return NULL;
}


/* ;; GABA:
   (class
     (name spki_dsa)
     (super spki_algorithm)
     (vars
       (random object randomness)))
*/

static int do_spki_dsa_verify(struct verifier *s,
			      UINT32 length,
			      UINT8 *msg,
			      UINT32 signature_length,
			      UINT8 * signature_data)
{
  CAST(dsa_verifier, self, s);
  struct simple_buffer buffer;
  struct sexp *e;
  mpz_t r, s;
  
  simple_buffer_init(&buffer, signature_length, signature_data);

  if ( (e = sexp_parse_canonical(&buffer))
       && parse_eod(buffer) )
    {
    }
}
    
static verifier *
make_spki_dsa_verifier(struct spki_algorithm *s UNUSED,
		       struct sexp_iterator *i)
{
  NEW(dsa_verifier, res);
  init_dsa_public(&res->public);

  if (spki_dsa_init_public_key(&res->public, i))
    {
      res->super.verify = do_spki_dsa_verify;
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

static signer *
make_spki_dsa_signer(struct spki_algorithm *s,
		     struct sexp_iterator *i)
{
  NEW(dsa_signer, signer);
  
}
#endif


#if 0
/* Encryption of private data.
 * Uses the format
 *
 * (password-encrypted LABEL sha1 ("3des-cbc" (iv #...#) (data #...#)))
 */
/* ;; GABA:
   (class
     (name spki_password_encrypt)
     (super command)
     (vars
       (label string)
       (hash . UINT32)
       (algorithm . UINT32)
       (iv string)
       (random object randomness)
       (crypto object crypto_instance)))
*/

static void
do_spki_encrypt(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(spki_password_encrypt, self, s);
  CAST_SUBTYPE(sexp, key, a);
  UINT32 pad;
  
  string lsh_string *s = SEXP_FORMAT(key, SEXP_CANONICAL, 0);
  pad = self->crypto->block_size - (s->length % self->crypto->block_size);

  if (pad)
    {
      UINT8 *p;
      s = ssh_format("%lfS%lr", s, pad, &p);
      RANDOM(self->random, pad, p);
    }

  CRYPT(self->crypto, s->length, s->data, s->data);

  COMMAND_RETURN(c,
		 sexp_l(4,
			SA(PASSWORD_ENCRYPTED),
			make_sexp_string(lsh_string_dup(self->label), NULL),
			sexp_a(self->hash),
			sexp_l(3,
			       sexp_a(self->algorithm),
			       make_sexp_string(lsh_string_dup(self->iv), NULL),
			       make_sexp_string(s, NULL),
			       -1),
			-1));
}

#endif
