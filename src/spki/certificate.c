/* SPKI functions */

#include "certificate.h"

#include "nettle/md5.h"
#include "nettle/sha.h"

#include "nettle/sexp.h"

#include <stdlib.h>
#include <string.h>

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



/* ACL database */
struct spki_acl *
spki_acl_parse(struct spki_acl_db *db, struct sexp_iterator *i)
{
  NEW(db, struct spki_acl, acl);

  /* FIXME: How about detailed error reporting? */
  if (!acl)
    return NULL;

  if (!sexp_iterator_check_type(i, "acl"))
    return NULL;

  /* XXX */
  return NULL;  
}
