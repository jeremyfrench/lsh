/* SPKI functions */

#include "certificate.h"

#include "nettle/md5.h"
#include "nettle/sha.h"

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
  db->first_subject = NULL;
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

struct spki_subject *
spki_subject_add_key(struct spki_acl_db *db,
		     unsigned key_length,  const uint8_t *key)
{
  NEW (db, struct spki_subject, subject);
  if (!subject)
    return NULL;

  if (!(subject->key = spki_dup(db, key_length, key)))
    {
      FREE(db, subject);
      return NULL;
    }

  subject->key_length = key_length;

  if (!(subject->md5 = MALLOC(db, MD5_DIGEST_SIZE)))
    {
      FREE(db, subject->key);
      FREE(db, subject);
      return NULL;
    }
  
  if (!(subject->sha1 = MALLOC(db, SHA1_DIGEST_SIZE)))
    {
      FREE(db, subject->md5);
      FREE(db, subject->key);
      FREE(db, subject);
      return NULL;
    }

  {
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, key_length, key);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, subject->sha1);
  }

  {
    struct md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, key_length, key);
    md5_digest(&ctx, MD5_DIGEST_SIZE, subject->md5);
  }

  subject->next = db->first_subject;
  db->first_subject = subject;
  
  return subject;
}

struct spki_subject *
spki_subject_by_key(struct spki_acl_db *db,
		    unsigned key_length, const uint8_t *key)
{
  /* FIXME: Doesn't check hashes. */
  struct spki_subject *s;

  for (s = db->first_subject; s; s = s->next)
    if (s->key_length == key_length
	&& !memcmp(s->key, key, key_length))
      return s;
  
  return NULL;
}


