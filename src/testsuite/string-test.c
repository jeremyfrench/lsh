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

  s = S("colonize this");
  s = lsh_string_colonize(s, 2, 1);
  p = lsh_get_cstring(s);
  
  ASSERT(p && !strcmp(p, "co:lo:ni:ze: t:hi:s")) ;

  s = S("fo");
  s = lsh_string_colonize(s, 2, 1);
  p = lsh_get_cstring(s);
  
  ASSERT(p && !strcmp(p, "fo")) ;
 
  s = S("");
  s = lsh_string_colonize(s, 1, 1);
  p = lsh_get_cstring(s);
  
  ASSERT(p && !*p) ;
  
  s = S("colonize this");
  s = lsh_string_colonize( s, 1, 1);
  p = lsh_get_cstring(s);

  ASSERT(p && !strcmp(p, "c:o:l:o:n:i:z:e: :t:h:i:s")) ;
  
  s = S("");
  s = lsh_string_bubblebabble(s, 1);
  p = lsh_get_cstring(s);
  
  ASSERT(p && !strcmp(p, "xexax")) ;

  s = S("1234567890");
  s = lsh_string_bubblebabble(s, 1);
  p = lsh_get_cstring(s);
  
  ASSERT(p && !strcmp(p, "xesef-disof-gytuf-katof-movif-baxux")) ;
  
  s = S("Pineapple");
  s = lsh_string_bubblebabble(s, 1);
  p = lsh_get_cstring(s);

  ASSERT(p && !strcmp(p, "xigak-nyryk-humil-bosek-sonax")) ;
           
  SUCCESS();
}
