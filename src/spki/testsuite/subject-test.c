#include "certificate.h"

#include <stdlib.h>

#define ASSERT(x) do { if (!(x)) abort(); } while(0)

int
main(int argc, char **argv)
{
  struct spki_acl_db db;
  struct spki_subject *s;
  
  spki_acl_init(&db);
  
  s = spki_subject_add_key(&db, 5, "3:foo");
  ASSERT(s);

  ASSERT(spki_subject_by_key(&db, 5, "3:foo") == s);
  ASSERT(spki_subject_by_key(&db, 5, "3:bar") == NULL);

  return 0;
}
