/* bignum.h
 *
 * Interface and conversion functions for GMP.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include <gmp.h>

#include "lsh_types.h"
#include "randomness.h"

void bignum_parse_s(mpz_t n, UINT32 length, UINT8 *data);
void bignum_parse_u(mpz_t n, UINT32 length, UINT8 *data);

UINT32 bignum_format_s(mpz_t n, UINT8 *data);
UINT32 bignum_format_s_length(mpz_t n);

UINT32 bignum_format_u(mpz_t n, UINT8 *data);
UINT32 bignum_format_u_length(mpz_t n);

/* Generates a random number in the interval 0 <= x < n */
void bignum_random(mpz_t x, struct randomness *random, mpz_t n);

#endif /* LSH_BIGNUM_H_INCLUDED */
