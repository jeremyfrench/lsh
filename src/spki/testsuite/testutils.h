#include "certificate.h"
#include "parse.h"
#include "spki-types.h"

#include "nettle/sexp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(msg) do { fprintf(stderr, "%s\n", msg); abort(); } while(0)

#define ASSERT(x) do { if (!(x)) FAIL("ASSERT failure: " #x); } while(0)

#define LLENGTH(x) (sizeof(x) - 1)
#define LDATA(x) (sizeof(x) - 1), x

void
test_main(void);
