/* bignum.h
 *
 * Interface and conversion functions for GMP.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include <gmp.h>

#define bignum mpz_t

void parse_bignum(bignum n, UINT32 length, UINT8 *data);
UINT32 bignum_format_length(bignum n);
void bignum_format(bignum n, UINT8 *data);

#endif /* LSH_BIGNUM_H_INCLUDED */
