/* certificate.h */

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

#ifndef LIBSPKI_CERTIFICATE_H_INCLUDED
#define LIBSPKI_CERTIFICATE_H_INCLUDED

#include "nettle/md5.h"
#include "nettle/sha.h"
#include "nettle/realloc.h"

/* Real declaration in parse.h */
struct spki_iterator;

struct spki_tag;

#include <time.h>

struct spki_hashes
{
  /* Include the flags in this struct? */
  uint8_t md5[MD5_DIGEST_SIZE];
  uint8_t sha1[SHA1_DIGEST_SIZE];
};

enum spki_principal_flags
  {
    SPKI_PRINCIPAL_MD5 = 1,
    SPKI_PRINCIPAL_SHA1 = 2
  };

struct spki_principal
{
  /* Principals linked into a list. */
  struct spki_principal *next;
  
  /* An s-expression */
  unsigned key_length;
  /* NULL if only hash is known */
  uint8_t *key;

  /* A flag is set iff the corresponding hash value is known. */
  enum spki_principal_flags flags;
  struct spki_hashes hashes;

  /* Information needed to verify signatures for this key. */
  void *verifier;
};
  
enum spki_5_tuple_flags
{
  SPKI_PROPAGATE = 1,
  SPKI_NOT_BEFORE = 2,
  SPKI_NOT_AFTER = 4,
};

/* Dates are represented as 19-character strings of the form
 * "1997-07-26_23:15:10". Note that dates can be compared by
 * memcmp. */

#define SPKI_DATE_SIZE 19

struct spki_date {
  uint8_t date[SPKI_DATE_SIZE];
};

void
spki_date_from_time_t(struct spki_date *d, time_t t);

/* Return value < 0, == 0 or > 0 if d < t, d == t or d > t */ 
int
spki_date_cmp_time_t(struct spki_date *d, time_t t);

struct spki_5_tuple
{
  /* ACL:s are linked into a list. */
  struct spki_5_tuple *next;

  /* NULL for ACL:s */
  struct spki_principal *issuer;
  
  /* For now, support only subjects that are principals (i.e. no
   * names) */
  struct spki_principal *subject;
  enum spki_5_tuple_flags flags;

  /* Checked if the corresponding flag is set. */
  struct spki_date not_before;
  struct spki_date not_after;

  /* Tag in internal representation. */
  struct spki_tag *tag;
};

struct spki_acl_db
{
  /* For custom memory allocation. */

  void *realloc_ctx;
  nettle_realloc_func *realloc;

  struct spki_principal *first_principal;
  struct spki_5_tuple *first_acl;
};

void
spki_acl_init(struct spki_acl_db *db);


/* Looks up a principal by key or by hash, and creates new principals
 * when needed. */

struct spki_principal *
spki_principal_by_key(struct spki_acl_db *db,
		      unsigned key_length, const uint8_t *key);

struct spki_principal *
spki_principal_by_md5(struct spki_acl_db *db, const uint8_t *digest);

struct spki_principal *
spki_principal_by_sha1(struct spki_acl_db *db, const uint8_t *digest);


/* Handling the acl database */
int
spki_acl_parse(struct spki_acl_db *db, struct spki_iterator *i);

const struct spki_5_tuple *
spki_acl_by_principal_first(struct spki_acl_db *,
			    unsigned principal_length,
			    uint8_t *principal);

const struct spki_5_tuple *
spki_acl_by_principal_next(struct spki_acl_db *db,
			   const struct spki_5_tuple *acl,
			   unsigned principal_length,
			   uint8_t *principal);

const struct spki_5_tuple *
spki_acl_by_authorization_first(struct spki_acl_db *db,
				struct spki_tag *authorization);

const struct spki_5_tuple *
spki_acl_by_authorization_next(struct spki_acl_db *db,
			       const struct spki_5_tuple *acl,
			       struct spki_tag *authorization);


/* Certificates */

void
spki_5_tuple_free_chain(struct spki_acl_db *db,
			struct spki_5_tuple *chain);

struct spki_5_tuple *
spki_process_sequence_no_signatures(struct spki_acl_db *db,
				    struct spki_iterator *i);


/* Other more or less internal functions. */

#define SPKI_MALLOC(db, size) ((db)->realloc((db)->realloc_ctx, NULL, (size)))
#define SPKI_FREE(db, p) ((db)->realloc((db)->realloc_ctx, (p), 0))

#define SPKI_NEW(db, type, var) type *var = SPKI_MALLOC((db), sizeof(type))

uint8_t *
spki_dup(struct spki_acl_db *db,
	 unsigned length, const uint8_t *data);

#endif /* LIBSPKI_CERTIFICATE_H_INCLUDED */
