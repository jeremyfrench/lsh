#ifndef LSH_TESTUTILS_H_INCLUDED
#define LSH_TESTUTILS_H_INCLUDED

#include "lsh.h"

#include "algorithms.h"
#include "crypto.h"
#include "format.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

struct lsh_string *
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

void
test_hash(const char *name,
	  const struct hash_algorithm *algorithm,
	  const struct lsh_string *data,
	  const struct lsh_string *digest);

void
test_mac(const char *name,
	 struct mac_algorithm *algorithm,
	 const struct lsh_string *key,
	 const struct lsh_string *data,
	 const struct lsh_string *digest);

void
test_sign(const char *name,
	  const struct lsh_string *key_exp,
	  struct lsh_string *msg,
	  const struct lsh_string *signature);

#define H(x) decode_hex(x)
#define S(x) make_string(x)

#define FAIL() abort()
#define SKIP() exit(77)
#define SUCCESS() return EXIT_SUCCESS

#define ASSERT(x) do { if (!(x)) FAIL(); } while(0)

#endif /* LSH_TESTUTILS_H_INCLUDED */
