#include "testutils.h"

int
test_main(void)
{
  struct lsh_string *s;
  const char *p;
  
  s = S("foo");
  p = lsh_get_cstring(s);

  ASSERT(p && !strcmp(p, "foo")) ;

  s = H("66006f");
  ASSERT(!lsh_get_cstring(s));

  s = H("6600");
  ASSERT(!lsh_get_cstring(s));

  s = H("");
  p = lsh_get_cstring(s);
  ASSERT(p && !*p);

  SUCCESS();
}
