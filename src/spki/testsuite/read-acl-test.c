#include "testutils.h"

void
test_main(void)
{
  struct spki_acl_db db;
  struct sexp_iterator i;
  
  spki_acl_init(&db);

  ASSERT(sexp_iterator_first
	 (&i, LDATA
	  ("(3:acl(7:version1:\0)(5:entry"
	   "(4:hash3:md516:xxxxxxxxxxxxxxxx)"
	   "(3:tag(3:ftp18:ftp.lysator.liu.se)))"
	   "(5:entry(10:public-key2:k1)"
	   "(3:tag(4:http32:http://www.lysator.liu.se/~nisse4:read))))")));

  ASSERT(spki_acl_parse(&db, &i));

  ASSERT(spki_principal_by_key(&db, LDATA("k1")));
  ASSERT(spki_principal_by_md5(&db, "xxxxxxxxxxxxxxxx"));
}
		    
			       
