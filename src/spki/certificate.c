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

#define HASH(result, method, length, data)			\
do {								\
  struct method##_ctx ctx;					\
  method##_init(&ctx);						\
  method##_update(&ctx, length, data);				\
  method##_digest(&ctx, sizeof(result->method), result->method);	\
} while (0)
  
static void
hash_data(struct spki_hashes *hashes,
	  unsigned length, const uint8_t *data)
{
  HASH(hashes, md5, length, data);
  HASH(hashes, sha1, length, data);
}
#undef HASH

static struct spki_principal *
spki_principal_add_key(struct spki_acl_db *db,
		       unsigned key_length,  const uint8_t *key,
		       const struct spki_hashes *hashes)
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

  if (hashes)
    principal->hashes = *hashes;
  else
    hash_data(&principal->hashes, key_length, key);

  principal->flags = SPKI_PRINCIPAL_MD5 | SPKI_PRINCIPAL_SHA1;
  
  principal->next = db->first_principal;
  db->first_principal = principal;
  
  return principal;
}

static struct spki_principal *
spki_principal_add_md5(struct spki_acl_db *db,
		       const uint8_t *md5)
{
  NEW (db, struct spki_principal, principal);
  if (!principal)
    return NULL;

  principal->key = NULL;

  memcpy(principal->hashes.md5, md5, sizeof(principal->hashes.md5));
  principal->flags = SPKI_PRINCIPAL_MD5;
  
  principal->next = db->first_principal;
  db->first_principal = principal;
  
  return principal;
}

static struct spki_principal *
spki_principal_add_sha1(struct spki_acl_db *db,
			const uint8_t *sha1)
{
  NEW (db, struct spki_principal, principal);
  if (!principal)
    return NULL;

  principal->key = NULL;

  memcpy(principal->hashes.sha1, sha1, sizeof(principal->hashes.sha1));
  principal->flags = SPKI_PRINCIPAL_SHA1;
  
  principal->next = db->first_principal;
  db->first_principal = principal;
  
  return principal;
}

struct spki_principal *
spki_principal_by_key(struct spki_acl_db *db,
		      unsigned key_length, const uint8_t *key)
{
  struct spki_principal *s;
  struct spki_hashes hashes;

  hash_data(&hashes, key_length, key);
  
  for (s = db->first_principal; s; s = s->next)
    {
      if (s->key)
	{
	  /* The key is known */
	  if (s->key_length == key_length
	      && !memcmp(s->key, key, key_length))
	    return s;
	}
      else
	/* Check hashes, exactly one should be present */
	if ( (s->flags == SPKI_PRINCIPAL_MD5
	      && !memcmp(s->hashes.md5, hashes.md5, sizeof(hashes.md5)))
	     || (s->flags == SPKI_PRINCIPAL_SHA1
		 && !memcmp(s->hashes.sha1, hashes.sha1, sizeof(hashes.sha1))))
	  {
	    s->key = spki_dup(db, key_length, key);
	    if (!s->key)
	      return NULL;
	    s->key_length = key_length;
	    s->hashes = hashes;
	    s->flags |= (SPKI_PRINCIPAL_MD5 | SPKI_PRINCIPAL_SHA1);
	  }
    }

  /* Add a new entry */
  return spki_principal_add_key(db, key_length, key, &hashes);
}

struct spki_principal *
spki_principal_by_md5(struct spki_acl_db *db, const uint8_t *digest)
{
  struct spki_principal *s;

  for (s = db->first_principal; s; s = s->next)
    if ( (s->flags & SPKI_PRINCIPAL_MD5)
	 && !memcmp(s->hashes.md5, digest, sizeof(s->hashes.md5)))
      return s;

  return spki_principal_add_md5(db, digest);
}

struct spki_principal *
spki_principal_by_sha1(struct spki_acl_db *db, const uint8_t *digest)
{
  struct spki_principal *s;

  for (s = db->first_principal; s; s = s->next)
    if ( (s->flags & SPKI_PRINCIPAL_SHA1)
	 && !memcmp(s->hashes.sha1, digest, sizeof(s->hashes.sha1)))
      return s;
  
  return spki_principal_add_sha1(db, digest);
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

/* NOTE: Uses SPKI_TYPE_UNKNOWN (= 0) for both unknown types and
 * syntax errors. */
enum spki_type
spki_get_type(struct sexp_iterator *i)
{
  if (i->type == SEXP_END)
    return SPKI_TYPE_END_OF_EXPR;

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
    return sexp_iterator_next(i);

  *i = before;
  return 0;    
}


/* ACL database */

static struct spki_principal *
parse_principal(struct spki_acl_db *db, struct sexp_iterator *i)
{
  struct sexp_iterator before = *i;

  switch (spki_get_type(i))
    {
    default:
      return NULL;

    case SPKI_TYPE_PUBLIC_KEY:
      {
	const uint8_t *key;
	unsigned key_length;
	
	*i = before;
	key = sexp_iterator_subexpr(i, &key_length);

	if (key)
	  return spki_principal_by_key(db, key_length, key);

	return NULL;
      }

    case SPKI_TYPE_HASH:
      {
	enum spki_type type = spki_intern(i);
	
	if (type
	    && i->type == SEXP_ATOM
	    && !i->display)
	  {
	    unsigned digest_length = i->atom_length;
	    const uint8_t *digest = i->atom;

	    if (sexp_iterator_next(i)
		&& i->type == SEXP_END
		&& sexp_iterator_exit_list(i))
	      {
		if (type == SPKI_TYPE_MD5
		    && digest_length == MD5_DIGEST_SIZE)
		  return spki_principal_by_md5(db, digest);

		else if (type == SPKI_TYPE_SHA1
			 && digest_length == SHA1_DIGEST_SIZE)
		  return spki_principal_by_sha1(db, digest);
	      }
	  }
	return NULL;
      }
    }
}

static int
parse_tag_body(struct spki_acl_db *db, struct sexp_iterator *i,
	       struct spki_5_tuple *tuple)
{
  const uint8_t *tag;

  return ((tag = sexp_iterator_subexpr(i, &tuple->tag_length))
	  && i->type == SEXP_END
	  && sexp_iterator_exit_list(i)
	  && (tuple->tag = spki_dup(db, tuple->tag_length, tag)));
}

static int
parse_tag(struct spki_acl_db *db, struct sexp_iterator *i,
	  struct spki_5_tuple *tuple)
{
  return spki_check_type(i, SPKI_TYPE_TAG)
    && parse_tag_body(db, i, tuple);
}

static int
parse_valid(struct sexp_iterator *i, struct spki_5_tuple *tuple)
{
  /* FIXME: Not implemented */
  return sexp_iterator_exit_list(i);
}

static int
parse_version(struct sexp_iterator *i)
{
  uint32_t version;
  return (sexp_iterator_get_uint32(i, &version)
	  && i->type == SEXP_END
	  && sexp_iterator_exit_list(i)
	  && (version == 0));
}

static struct spki_5_tuple *
parse_acl_entry(struct spki_acl_db *db, struct sexp_iterator *i)
{
  /* Syntax:
   *
   * ("entry" <principal> <delegate>? <tag> <valid>? <comment>?) */
  if (!spki_check_type(i, SPKI_TYPE_ENTRY))
    return NULL;
  else
    {
      NEW(db, struct spki_5_tuple, acl);

      if (!acl)
	return NULL;

      acl->issuer = NULL;
      acl->flags = 0;
      acl->tag = NULL;

      acl->subject = parse_principal(db, i);
      if (!acl->subject)
	goto fail;

      if (spki_check_type(i, SPKI_TYPE_PROPAGATE))
	{
	  if (i->type != SEXP_END
	      || !sexp_iterator_exit_list(i))
	    goto fail;

	  acl->flags |= SPKI_PROPAGATE;
	}

      if (!parse_tag(db, i, acl))
	goto fail;

      if (spki_check_type(i, SPKI_TYPE_COMMENT)
	  && !sexp_iterator_exit_list(i))
	goto fail;

      if (spki_check_type(i, SPKI_TYPE_VALID))
	/* Not implemented */
	goto fail;

      if (i->type == SEXP_END
	  && sexp_iterator_exit_list(i))
	return acl;

    fail:
      if (acl->tag)
	FREE(db, acl->tag);
      FREE(db, acl);
      return NULL;
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
  
  if (spki_check_type(i, SPKI_TYPE_VERSION) && !parse_version(i))
    return 0;
  
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

static enum spki_type
parse_skip_optional(struct sexp_iterator *i)
{
  return sexp_iterator_exit_list(i) ? spki_get_type(i) : SPKI_TYPE_UNKNOWN;
}

#define SKIP(t) do				\
{						\
  if (type == (t))				\
    type = parse_skip_optional(i);		\
} while (0)

#define PRINCIPAL(p)				\
(						\
  p = parse_principal(db, i),			\
  p = (p && i->type == SEXP_END			\
       && sexp_iterator_exit_list(i)		\
       && (type = spki_get_type(i)))		\
      ? p : NULL				\
)

/* Should be called with the iterator pointing just after the "cert"
 * type tag. */
int
spki_cert_parse_body(struct spki_acl_db *db, struct sexp_iterator *i,
		     struct spki_5_tuple *cert)
{
  enum spki_type type = spki_get_type(i);

  cert->flags = 0;
  
  if (type == SPKI_TYPE_VERSION)
    {
      if (!parse_version(i))
	return 0;
      
      type == spki_get_type(i);
    }

  SKIP(SPKI_TYPE_DISPLAY);

  if (type != SPKI_TYPE_ISSUER)
    return 0;

  if (!PRINCIPAL(cert->issuer))
    return 0;

  SKIP(SPKI_TYPE_ISSUER_INFO);

  /* For now, support only subjects of type public-key and hash. */
  if (!PRINCIPAL(cert->subject))
    return 0;
  
  SKIP(SPKI_TYPE_SUBJECT_INFO);

  if (type == SPKI_TYPE_PROPAGATE)
    {
      if (!sexp_iterator_exit_list(i))
	return 0;

      cert->flags |= SPKI_PROPAGATE;
    }

  if (type != SPKI_TYPE_TAG)
    return 0;
  
  if (!parse_tag_body(db, i, cert))
    return 0;

  type = spki_get_type(i);

  if (type == SPKI_TYPE_VALID)
    {
      if (!parse_valid(i, cert))
	return 0;

      type = spki_get_type(i);
    }

  SKIP(SPKI_TYPE_COMMENT);

  return (type == SPKI_TYPE_END_OF_EXPR) && sexp_iterator_exit_list(i);
}

int
spki_cert_parse(struct spki_acl_db *db, struct sexp_iterator *i,
		struct spki_5_tuple *cert)
{
  return spki_check_type(i, SPKI_TYPE_CERT)
    && spki_cert_parse_body(db, i, cert);
}
     
