/* bignum.h
 *
 * Interface and conversion functions for GMP.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include <gmp.h>
#include "lsh_types.h"

#define bignum MP_INT

void parse_bignum(bignum *n, UINT32 length, UINT8 *data);
UINT32 bignum_format_length(bignum *n);
UINT32 bignum_format(bignum *n, UINT8 *data);

#endif /* LSH_BIGNUM_H_INCLUDED */
