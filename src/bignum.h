/* bignum.h
 *
 * Interface and conversion functions for GMP.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include "lsh_types.h"
#include "randomness.h"

/* Needed for the declaration of mpz_out_str */
#include <stdio.h>

#include <gmp.h>

void bignum_parse_s(mpz_t n, UINT32 length, UINT8 *data);
void bignum_parse_u(mpz_t n, UINT32 length, UINT8 *data);

UINT32 bignum_format_s(mpz_t n, UINT8 *data);
UINT32 bignum_format_s_length(mpz_t n);

UINT32 bignum_format_u(mpz_t n, UINT8 *data);
UINT32 bignum_format_u_length(mpz_t n);

/* Generates a random number in the interval 0 <= x < n */
void bignum_random(mpz_t x, struct randomness *random, mpz_t n);

#endif /* LSH_BIGNUM_H_INCLUDED */
