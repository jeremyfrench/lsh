#include "testutils.h"

void
test_main(void)
{
  struct spki_acl_db db;
  const struct spki_5_tuple *acl;
  struct spki_principal *k1;
  struct spki_principal *k2;
  struct spki_tag *tag;
  
  spki_acl_init(&db);

  read_acl(&db, LDATA
	   ("(3:acl(5:entry(7:subject(10:public-key2:k1))"
	    "(3:tag(3:ftp2:h1)))"
	    "(5:entry(7:subject(10:public-key2:k2))"
	    "(3:tag(3:ftp(1:*3:set2:h12:h22:h3)))))"));

  k1 = spki_principal_by_key(&db, LDATA("(10:public-key2:k1)"));
  ASSERT(k1);

  k2 = spki_principal_by_key(&db, LDATA("(10:public-key2:k2)"));
  ASSERT(k2);

  ASSERT(k1 != k2);

  tag = make_tag(LDATA("(4:http)"));
  acl = spki_acl_by_authorization_first(&db, tag);
  ASSERT(!acl);
  acl = spki_acl_by_authorization_next(&db, acl, tag);
  ASSERT(!acl);
  release_tag(tag);

  tag = make_tag(LDATA("(3:ftp)"));
  acl = spki_acl_by_authorization_first(&db, tag);
  ASSERT(!acl);
  release_tag(tag);

  tag = make_tag(LDATA("(3:ftp2:h5)")); 
  acl = spki_acl_by_authorization_first(&db, tag);
  ASSERT(!acl);
  release_tag(tag);

  tag = make_tag(LDATA("(3:ftp2:h1)"));
  acl = spki_acl_by_authorization_first(&db, tag);
  ASSERT(acl);
  ASSERT(acl->subject == k2);
  acl = spki_acl_by_authorization_next(&db, acl, tag);
  ASSERT(acl);
  ASSERT(acl->subject == k1);
  ASSERT(!spki_acl_by_authorization_next(&db, acl, tag));
  release_tag(tag);

  tag = make_tag(LDATA("(3:ftp2:h2)"));
  acl = spki_acl_by_authorization_first(&db, tag);
  ASSERT(acl);
  ASSERT(acl->subject == k2);
  ASSERT(!spki_acl_by_authorization_next(&db, acl, tag));
  release_tag(tag);
}
