/* bignum.h
 *
 * Interface and conversion functions for GMP.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include <gmp.h>

#include "lsh_types.h"
#include "randomness.h"

#define bignum mpz_t

void bignum_parse(bignum n, UINT32 length, UINT8 *data);
UINT32 bignum_format_length(bignum n);
UINT32 bignum_format(bignum n, UINT8 *data);

/* Generates a random number in the interval 0 <= x < n */
void bignum_random(bignum x, struct randomness *random, bignum n);

#endif /* LSH_BIGNUM_H_INCLUDED */
