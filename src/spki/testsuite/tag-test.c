#include "testutils.h"

static int
includes(unsigned alength, const uint8_t *adata,
	 unsigned blength, const uint8_t *bdata)
{
  struct sexp_iterator a;
  struct sexp_iterator b;
  
  ASSERT(sexp_iterator_first(&a, alength, adata));
  ASSERT(sexp_iterator_first(&b, blength, bdata));

  if (spki_tag_includes(&a, &b))
    {
      ASSERT(a.type == SEXP_END);
      ASSERT(b.type == SEXP_END);
      return 1;
    }
  else
    return 0;
}

#define INCLUDES(a, b) includes(LDATA(a), LDATA(b))

void
test_main(void)
{
  ASSERT(INCLUDES("(3:ftp18:ftp.lysator.liu.se)",
		  "(3:ftp18:ftp.lysator.liu.se)"));

  ASSERT(!INCLUDES("(3:ftp18:ftp.lysator.liu.se)",
		   "(4:http18:ftp.lysator.liu.se)"));
  

  ASSERT(INCLUDES("(3:ftp18:ftp.lysator.liu.se)",
		  "(3:ftp18:ftp.lysator.liu.se4:read)"));

  ASSERT(!INCLUDES("(3:ftp18:ftp.lysator.liu.se4:read)",
		   "(3:ftp18:ftp.lysator.liu.se)"));

  ASSERT(INCLUDES("(1:*)", "(3:foo)"));
  ASSERT(!INCLUDES("(3:foo)", "(1:*)"));

  ASSERT(INCLUDES("(1:*)",
		  "(1:*3:set3:foo3:bar)"));
  ASSERT(!INCLUDES("(1:*3:set3:foo3:bar)",
		   "(1:*)"));

  ASSERT(INCLUDES("(1:*3:set(3:foo)(3:bar))",
		  "(3:foo)"));
  ASSERT(INCLUDES("(1:*3:set(3:foo)(3:bar))",
		  "(3:foo4:read)"));
  ASSERT(INCLUDES("(1:*3:set(3:foo)(3:bar))",
		  "(3:bar)"));
  ASSERT(!INCLUDES("(1:*3:set(3:foo)(3:bar))",
		   "(3:baz)"));

  /* Set inclusions not implemented. */
#if 0
  ASSERT(INCLUDES("(1:*3:set(3:foo)(3:bar))",
		  "(1:*3:set(3:foo))"));
  ASSERT(INCLUDES("(1:*3:set(3:foo)(3:bar))",
		  "(1:*3:set(3:foo)(3:bar))"));
  ASSERT(!INCLUDES("(1:*3:set(3:foo)(3:bar))",
		   "(1:*3:set(3:foo)(3:bar)(3:baz))"));
  ASSERT(!INCLUDES("(1:*3:set(3:foo)(3:bar))",
		   "(1:*3:set(3:foo)(3:baz))"));
#endif
}
