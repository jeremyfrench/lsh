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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_BIGNUM_H_INCLUDED
#define LSH_BIGNUM_H_INCLUDED

#include "lsh.h"

/* Needed for the declaration of mpz_out_str */
#include <stdio.h>

#if HAVE_GMP2_GMP_H
#include <gmp2/gmp.h>
#else
#if HAVE_GMP_H
#include <gmp.h>
#else
#error No gmp.h!
#endif
#endif

/* Generates a random number in the interval 0 <= x < n */
void bignum_random(mpz_t x, struct randomness *random, mpz_t n);

#endif /* LSH_BIGNUM_H_INCLUDED */
