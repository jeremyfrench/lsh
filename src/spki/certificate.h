/* certificate.h */

#include "nettle/sexp.h"

#include <time.h>

/* FIXME: Terminology: Should this be a "subject" or a "principal"? */
struct spki_subject
{
  /* Subjects linked into a list. */
  struct spki_subject *next;
  
  /* An s-expression */
  unsigned key_length;
  /* NULL if only hash is known */
  uint8_t *key;

  /* NULL if not known. */
  uint8_t *md5;
  uint8_t *sha1;

  /* Information needed to verify signatures for this key. */
  void *verifier;
};

#if 0
struct spki_authorization
{
  /* Next sibling */
  struct spki_authorization *next;
  enum spki_tag_type {
    SPKI_TAG_ATOM,
    SPKI_TAG_LIST,
    SPKI_TAG_PREFIX,
    SPKI_TAG_SET
  } type;

  union {
  }  
};
#endif
  
enum spki_flags
{
  SPKI_PROPAGATE = 1,
  SPKI_NOT_BEFORE = 2,
  SPKI_NOT_AFTER = 4,
};

struct spki_acl
{
  /* ACL:s are linked into a list. */
  struct spki_acl *next;
  
  struct spki_subject *principal;
  enum spki_flags flags;

  /* Checked if the correspondign flag is set. */
  time_t not_before;
  time_t not_after;

  /* An s-expression */
  /* FIXME: Parse into some internal representation? */
  unsigned tag_length;
  uint8_t tag;
};

struct spki_acl_db
{
  /* For custom memory allocation. */
  void *(*realloc)(struct spki_acl_db *, void *, unsigned);

  struct spki_subject *first_subject;
  struct spki_acl *first_acl;
};

void
spki_acl_init(struct spki_acl_db *db);

/* Internal functions for looking up a subject. */

struct spki_subject *
spki_subject_add_key(struct spki_acl_db *db,
		     unsigned key_length,  const uint8_t *key);

struct spki_subject *
spki_subject_by_key(struct spki_acl_db *db,
		    unsigned key_length, const uint8_t *key);

struct spki_subject *
spki_subject_by_md5(struct spki_acl_db *db,
		    unsigned key_length, const uint8_t *key);

struct spki_subject *
spki_subject_by_sha1(struct spki_acl_db *db,
		     unsigned key_length, const uint8_t *key);


/* Handling the acl database */
struct spki_acl *
spki_acl_parse(struct spki_acl_db *db, struct sexp_iterator *i);

struct spki_acl *
spki_acl_by_principal_first(struct spki_acl_db *,
			    unsigned principal_length,
			    uint8_t *principal);

struct spki_acl *
spki_acl_by_principal_next(struct spki_acl_db *,
			   struct spki_acl *acl,
			   unsigned principal_length,
			   uint8_t *principal);

struct spki_acl *
spki_acl_by_authorization_first(struct spki_acl_db *,
			    unsigned authorization_length,
			    uint8_t *authorization);

struct spki_acl *
spki_acl_by_authorization_next(struct spki_acl_db *,
			       struct spki_acl *acl,
			       unsigned authorization_length,
			       uint8_t *authorization);
