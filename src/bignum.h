/* bignum.h
 *
 * Interface and conversion functions for GMP.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include <gmp.h>

#include "lsh_types.h"
#include "randomness.h"

void bignum_parse(mpz_t n, UINT32 length, UINT8 *data);
UINT32 bignum_format_length(mpz_t n);
UINT32 bignum_format(mpz_t n, UINT8 *data);

/* Generates a random number in the interval 0 <= x < n */
void bignum_random(mpz_t x, struct randomness *random, mpz_t n);

#endif /* LSH_BIGNUM_H_INCLUDED */
