/* SPKI functions */

#include "certificate.h"

#include "nettle/md5.h"
#include "nettle/sha.h"

#include "nettle/sexp.h"

#include <stdlib.h>
#include <string.h>

/* Automatically generated files */

/* FIXME: Is there any way to get gperf to declare this function
 * static? */
const struct spki_assoc *
spki_gperf (const char *str, unsigned int len);

#include "spki-gperf.h"
#include "spki-type-names.h"

static void *
spki_realloc(struct spki_acl_db *db, void *p, unsigned size)
{
  return realloc(p, size);
}

#define MALLOC(db, size) ((db)->realloc((db), NULL, (size)))
#define FREE(db, p) ((db)->realloc((db), (p), 0))

#define NEW(db, type, var) type *var = MALLOC((db), sizeof(type))

void
spki_acl_init(struct spki_acl_db *db)
{
  db->realloc = spki_realloc;
  db->first_principal = NULL;
  db->first_acl = NULL;
}

static uint8_t *
spki_dup(struct spki_acl_db *db,
	 unsigned length, const uint8_t *data)
{
  uint8_t *n = MALLOC(db, length);

  if (n)
    memcpy(n, data, length);

  return n;
}

struct spki_principal *
spki_principal_add_key(struct spki_acl_db *db,
		     unsigned key_length,  const uint8_t *key)
{
  NEW (db, struct spki_principal, principal);
  if (!principal)
    return NULL;

  if (!(principal->key = spki_dup(db, key_length, key)))
    {
      FREE(db, principal);
      return NULL;
    }

  principal->key_length = key_length;

  if (!(principal->md5 = MALLOC(db, MD5_DIGEST_SIZE)))
    {
      FREE(db, principal->key);
      FREE(db, principal);
      return NULL;
    }
  
  if (!(principal->sha1 = MALLOC(db, SHA1_DIGEST_SIZE)))
    {
      FREE(db, principal->md5);
      FREE(db, principal->key);
      FREE(db, principal);
      return NULL;
    }

  {
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, key_length, key);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, principal->sha1);
  }

  {
    struct md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, key_length, key);
    md5_digest(&ctx, MD5_DIGEST_SIZE, principal->md5);
  }

  principal->next = db->first_principal;
  db->first_principal = principal;
  
  return principal;
}

struct spki_principal *
spki_principal_by_key(struct spki_acl_db *db,
		    unsigned key_length, const uint8_t *key)
{
  /* FIXME: Doesn't check hashes. */
  struct spki_principal *s;

  for (s = db->first_principal; s; s = s->next)
    if (s->key_length == key_length
	&& !memcmp(s->key, key, key_length))
      return s;
  
  return NULL;
}



enum spki_type
spki_intern(struct sexp_iterator *i)
{  
  if (i->type == SEXP_ATOM
      && !i->display)
    {
      const struct spki_assoc *assoc = spki_gperf(i->atom, i->atom_length);

      if (assoc && sexp_iterator_next(i))
	return assoc->id;
    }
  
  return 0;
}

enum spki_type
spki_get_type(struct sexp_iterator *i)
{
  return sexp_iterator_enter_list(i) ? spki_intern(i) : 0;
}

/* If the type doesn't match, don't move the iterator. */
/* FIXME: static because enum spki_type isn't defined in the header
 * file. */
static int
spki_check_type(struct sexp_iterator *i, enum spki_type type)
{
  struct sexp_iterator before = *i;
  
  if (sexp_iterator_enter_list(i)
      && i->type == SEXP_ATOM
      && !i->display
      && i->atom_length == spki_type_names[type].length
      && !memcmp(i->atom,
		 spki_type_names[type].name,
		 spki_type_names[type].length))
    return 1;

  *i = before;
  return 0;    
}


/* ACL database */

static struct spki_principal *
parse_principal(struct spki_acl_db *db, struct sexp_iterator *i)
{
  /* Not implemented */
  abort();
}

static struct spki_5_tuple *
parse_acl_entry(struct spki_acl_db *db, struct sexp_iterator *i)
{
  if (!spki_check_type(i, SPKI_TYPE_ENTRY))
    return NULL;
  else
    {
      NEW(db, struct spki_5_tuple, acl);

      if (!acl)
	return NULL;

      acl->issuer = NULL;
      acl->subject = NULL;
      acl->flags = 0;
      acl->tag = NULL;

      while (i->type != SEXP_END)
	{
	  enum spki_type type = spki_get_type(i);

	  switch(type)
	    {
	    default:
	      goto fail;
	      
	    case SPKI_TYPE_SUBJECT:
	      if (acl->subject)
		goto fail;
	      acl->subject = parse_principal(db, i);
	      if (!acl->subject)
		goto fail;

	      
	      break;

	    case SPKI_TYPE_PROPAGATE:
	      if (i->type != SEXP_END
		  || (acl->flags & SPKI_PROPAGATE)
		  || !sexp_iterator_exit_list(i))
		goto fail;

	      acl->flags |= SPKI_PROPAGATE;
	      break;

	    case SPKI_TYPE_TAG:
	      {
		const uint8_t *tag;
		if (acl->tag)
		  goto fail;
		
		tag = sexp_iterator_subexpr(i, &acl->tag_length);
		if (!tag || i->type != SEXP_END)
		  goto fail;
		
		tag = spki_dup(db, acl->tag_length, tag);
		if (!tag)
		  goto fail;
		break;
	      }
	    }
	}
      if (!sexp_iterator_exit_list(i))
	{
	fail:
	  if (acl->tag)
	    FREE(db, acl->tag);
	  FREE(db, acl);
	  return NULL;
	}
      return acl;
    }      
}

int
spki_acl_parse(struct spki_acl_db *db, struct sexp_iterator *i)
{
  if (!spki_check_type(i, SPKI_TYPE_ACL))
    return 0;

  if (i->type == SEXP_END)
    /* An empty acl is ok */
    return 1;
  
  if (spki_check_type(i, SPKI_TYPE_VERSION))
    {
      uint32_t version;
      if (sexp_iterator_get_uint32(i, &version)
	  && i->type != SEXP_END
	  && sexp_iterator_exit_list(i)
	  && !version)
	{
	  if (i->type == SEXP_END)
	    /* Empty acl */
	    return 1;
	}
      return 0;
    }
  
  while (i->type != SEXP_END)
    {
      struct spki_5_tuple *acl = parse_acl_entry(db, i);
      if (!acl)
	return 0;

      acl->next = db->first_acl;
      db->first_acl = acl;
    }

  return 1;
}
