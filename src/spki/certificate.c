/* SPKI functions */

/* libspki
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "certificate.h"
#include "parse.h"
#include "spki-types.h"

#include "nettle/md5.h"
#include "nettle/sha.h"
#include "nettle/sexp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


static void *
spki_realloc(struct spki_acl_db *db UNUSED, void *p, unsigned size)
{
  return realloc(p, size);
}

void
spki_acl_init(struct spki_acl_db *db)
{
  db->realloc = spki_realloc;
  db->first_principal = NULL;
  db->first_acl = NULL;
}

uint8_t *
spki_dup(struct spki_acl_db *db,
	 unsigned length, const uint8_t *data)
{
  uint8_t *n = SPKI_MALLOC(db, length);

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
  SPKI_NEW(db, struct spki_principal, principal);
  if (!principal)
    return NULL;

  if (!(principal->key = spki_dup(db, key_length, key)))
    {
      SPKI_FREE(db, principal);
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
  SPKI_NEW(db, struct spki_principal, principal);
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
  SPKI_NEW(db, struct spki_principal, principal);
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



/* Automatically generated table. */
#include "spki-type-names.h"

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

int
spki_acl_parse(struct spki_acl_db *db, struct sexp_iterator *i)
{
  enum spki_type type;
  
  if (!spki_check_type(i, SPKI_TYPE_ACL))
    return 0;

  type = spki_parse_type(i);
 
  if (type == SPKI_TYPE_END_OF_EXPR)
    /* An empty acl is ok */
    return sexp_iterator_exit_list(i);
  
  if (type == SPKI_TYPE_VERSION)
    type = spki_parse_version(i);
  
  while (type == SPKI_TYPE_ENTRY)
    {
      SPKI_NEW(db, struct spki_5_tuple, acl);
      if (!acl)
	return 0;
      
      type = spki_parse_acl_entry(db, i, acl);
      if (!type)
	{
	  SPKI_FREE(db, acl);
	  return 0;
	}
      
      acl->next = db->first_acl;
      db->first_acl = acl;
    }

  return type == SPKI_TYPE_END_OF_EXPR && spki_parse_end(i);
}

#define SKIP(t) do				\
{						\
  if (type == (t))				\
    type = spki_parse_skip(i);			\
} while (0)

/* Should be called with the iterator pointing just after the "cert"
 * type tag. */
int
spki_cert_parse_body(struct spki_acl_db *db, struct sexp_iterator *i,
		     struct spki_5_tuple *cert)
{
  enum spki_type type = spki_parse_type(i);

  cert->flags = 0;
  
  if (type == SPKI_TYPE_VERSION)
    type = spki_parse_version(i);

  SKIP(SPKI_TYPE_DISPLAY);

  if (type != SPKI_TYPE_ISSUER)
    return 0;

  type = spki_parse_principal(db, i, &cert->issuer);
  if (!type || !(type = spki_parse_end(i)))
    return 0;

  SKIP(SPKI_TYPE_ISSUER_INFO);

  type = spki_parse_principal(db, i, &cert->subject);
  if (!type || !(type = spki_parse_end(i)))
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
  
  type = spki_parse_tag(db, i, cert);
  if (!type)
    return 0;

  if (type == SPKI_TYPE_VALID)
    type = spki_parse_valid(i, cert);

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
     


/* Dates */

static void
write_decimal(unsigned length, uint8_t *buffer, unsigned x)
{
  const unsigned msd[5] = { 0, 1, 10, 100, 1000 };
  unsigned digit;
  
  assert(length <= 4);

  for (digit = msd[length]; digit; digit /= 10)
    {
      /* NOTE: Will generate a bogus digit if x is too large. */
      *buffer++ = '0' + x / digit;
      x %= digit;
    }
}

void
spki_date_from_time_t(struct spki_date *d, time_t t)
{
  struct tm tm_storage;
  /* FIXME: Configure check for gmtime_r. */
  struct tm *tm = gmtime_r(&t, &tm_storage);

  if (!tm)
    /* When can gmtime_r fail??? */
    abort();

  d->date[4] = d->date[7] = '-';
  d->date[10] = '_';
  d->date[13] = d->date[16] = ':';
  
  write_decimal(4, d->date,   1900 + tm->tm_year);
  write_decimal(2, d->date +  5, 1 + tm->tm_mon);
  write_decimal(2, d->date +  8,     tm->tm_mday);
  write_decimal(2, d->date + 11,     tm->tm_hour);
  write_decimal(2, d->date + 14,     tm->tm_min);
  write_decimal(2, d->date + 17,     tm->tm_sec);
}

/* Returns -1, 0 or 1 if if d < t, d == t or d > t */ 
int
spki_date_cmp_time_t(struct spki_date *d, time_t t)
{
  struct spki_date d2;
  spki_date_from_time_t(&d2, t);
  return memcmp(d, &d2, SPKI_DATE_SIZE);
}
  
