#ifndef LSH_TESTUTILS_H_INCLUDED
#define LSH_TESTUTILS_H_INCLUDED

#include "lsh.h"

#include "algorithms.h"
#include "crypto.h"

#include <inttypes.h>
#include <stdlib.h>

const struct lsh_string *
decode_hex(const char *);

/* The main program */
int
test_main(void);

void
test_cipher(const char *name, struct crypto_algorithm *algorithm,
	    const struct lsh_string *key,
	    const struct lsh_string *plain,
	    const struct lsh_string *cipher,
	    const struct lsh_string *iv);
	    
#define H(x) decode_hex(x)

#define FAIL() abort()
#define SKIP() exit(77)
#define SUCCESS() return EXIT_SUCCESS

#endif /* LSH_TESTUTILS_H_INCLUDED */
