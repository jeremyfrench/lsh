/* certificate.h */

#include "nettle/sexp.h"

#include <time.h>

struct spki_principal
{
  /* Principals linked into a list. */
  struct spki_principal *next;
  
  /* An s-expression */
  unsigned key_length;
  /* NULL if only hash is known */
  uint8_t *key;

  uint8_t md5[MD5_DIGEST_SIZE];
  uint8_t sha[SHA1_DIGEST_SIZE];

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

struct spki_5_tuple
{
  /* ACL:s are linked into a list. */
  struct spki_5_tuple *next;

  /* NULL for ACL:s */
  struct spki_principal *issuer;
  
  /* For now, support only subjects that are principals (i.e. no
   * names) */
  struct spki_principal *subject;
  enum spki_flags flags;

  /* Checked if the corresponding flag is set. */
  time_t not_before;
  time_t not_after;

  /* An s-expression */
  /* FIXME: Parse into some internal representation? */
  unsigned tag_length;
  uint8_t *tag;
};

struct spki_acl_db
{
  /* For custom memory allocation. */
  void *(*realloc)(struct spki_acl_db *, void *, unsigned);

  struct spki_principal *first_principal;
  struct spki_5_tuple *first_acl;
};

void
spki_acl_init(struct spki_acl_db *db);

/* Internal functions for looking up a principal. */

struct spki_principal *
spki_principal_add_key(struct spki_acl_db *db,
		       unsigned key_length,  const uint8_t *key);

struct spki_principal *
spki_principal_by_key(struct spki_acl_db *db,
		      unsigned key_length, const uint8_t *key);

struct spki_principal *
spki_principal_by_md5(struct spki_acl_db *db, const uint8_t *digest);

struct spki_principal *
spki_principal_by_sha1(struct spki_acl_db *db, const uint8_t *digest);


/* Handling the acl database */
int
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


/* More-or-less internal function for parsing various expressions. */
enum spki_type
spki_intern(struct sexp_iterator *i);

enum spki_type
spki_get_type(struct sexp_iterator *i);
