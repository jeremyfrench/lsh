#include "testutils.h"

#include "certificate.h"
#include "nettle/sexp.h"

void
test_main(void)
{
  struct spki_acl_db db;
  struct sexp_iterator i;
  struct spki_5_tuple cert;
  
  spki_acl_init(&db);

  ASSERT(sexp_iterator_first
	 (&i, LDATA("(4:cert(6:issuer(10:public-key2:k1))"
		    "(7:subject(10:public-key2:k2))"
		    "(3:tag(3:foo))"
		    "(5:valid(10:not-before19:2000-05-05_00:00:00)"
		    "(9:not-after19:2002-01-01_00:00:00)))")));

  ASSERT(spki_cert_parse(&db, &i, &cert));

  ASSERT(cert.issuer ==
	 spki_principal_by_key(&db, LDATA("(10:public-key2:k1)")));
  ASSERT(cert.subject ==
	 spki_principal_by_key(&db, LDATA("(10:public-key2:k2)")));

#if 0
  ASSERT(cert.flags == SPKI_NOT_BEFORE | SPKI_NOT_AFTER);
#endif
}
	 
