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

void
test_main(void)
{
  ASSERT(includes(LDATA("(3:ftp18:ftp.lysator.liu.se)"),
		  LDATA("(3:ftp18:ftp.lysator.liu.se)")));

  ASSERT(!includes(LDATA("(3:ftp18:ftp.lysator.liu.se)"),
		   LDATA("(4:http18:ftp.lysator.liu.se)")));
  

  ASSERT(includes(LDATA("(3:ftp18:ftp.lysator.liu.se)"),
		  LDATA("(3:ftp18:ftp.lysator.liu.se4:read)")));

  ASSERT(!includes(LDATA("(3:ftp18:ftp.lysator.liu.se4:read)"),
		   LDATA("(3:ftp18:ftp.lysator.liu.se)")));
}
