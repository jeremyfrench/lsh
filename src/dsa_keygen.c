/* dss_keygen.c
 *
 * Generate dss key pairs..
 *
 * $Id$
 */

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

#include "dss_keygen.h"

#include "randomness.h"

#include "sha.h"

#include <assert.h>

/* The (slow) NIST method of generating DSA primes. Algorithm 4.56 of
 * Handbook of Applied Cryptography. */

#define SEED_LENGTH SHA_DIGESTSIZE
#define SEED_BITS (SEED_LENGTH * 8)

static void hash(mpz_t x, UINT8 *digest)
{
  mpz_t t;
  UINT8 data[SEED_LENGTH];
  struct sha_ctx ctx;
  
  mpz_init_set(t, x);
  mpz_fdiv_r_2exp(t, t, SEED_BITS);
  
  bignum_write(t, SEED_LENGTH, data);
  mpz_clear(t);

  sha_init(&ctx);
  sha_update(&ctx, data, SEED_LENGTH);
  sha_final(&ctx);
  sha_digest(&ctx, digest);
}

void dss_nist_gen(mpz_t p, mpz_t q, struct randomness *r, unsigned l)
{
  unsigned L;
  unsigned n, b;
  mpz_t s, t, c;
  
  assert(l <= 8);

  L = 512 + 64*l;
  n = (L-1) / 160; b = (L-1) % 160;

  mpz_init(s);
  mpz_init(t);
  mpz_init(c);
  
  while (1)
    {
      { /* Generate q */
	UINT8 h1[SHA_DIGESTSIZE];
	UINT8 h2[SHA_DIGESTSIZE];
	
	mpz_init(s);
	bignum_random_size(s, r, SEED_BITS);
	
	hash(s, h1);
	
	mpz_set(t, s);
	mpz_add_ui(t, t, 1);
	
	hash(t, h2);
	
	memxor(h1, h2, SHA_DIGESTSIZE);
	
	h1[0] |= 0x80;
	h1[SHA_DIGESTSIZE - 1] |= 1;
	
	bignum_parse_u(q, SHA_DIGESTSIZE, h1);
	
	if (bignum_small_factor(q, 1000)
	    || !mpz_probab_prime_p(q, 18))
	  /* Try new seed. */
	  continue;
      }
      /* q is a prime, with overwelming probability. */

      {
	unsigned size = (n+1) * SHA_DIGESTSIZE;
	UINT8 *buffer = alloca(size);
	unsigned i, j;
	
	for (i = 0, j = 2; i<4096; i++, j+= n+1)
	  {
	    unsigned k;
	    
	    for (k = 0; k<=n ; k++)
	      {
		mpz_set(t, s);
		mpz_add_ui(t, t, j + k);
		/* FIXME: See galb's bug report */
		hash(t, buffer + ( (n+1-k) * SHA_DIGESTSIZE));
	      }
	    bignum_parse_u(p, size, buffer);

	    mpz_fdiv_r_2exp(p, p, L);
	    mpz_setbit(p, L-1);

	    mpz_set(t, q);
	    mpz_mul_2exp(t, t, 1);

	    mpz_fdiv_r(c, p, t);

	    mpz_sub_ui(c, c, 1);

	    mpz_sub(p, p, c);

	    if (!bignum_small_factor(p, 1000)
		&& mpz_probab_prime_p(p, 5))
	      {
		/* Done! */
		mpz_clear(s);
		mpz_clear(t);
		mpz_clear(c);

		return;
	      }
	  }
      }
    }
}

void dss_find_generator(mpz_t g, struct randomness *r, mpz_t p, mpz_t q)
{
  mpz_t e;
  mpz_t n;
  
  /* e = (p-1)/q */
  mpz_init_set(e, p);
  mpz_sub_ui(e, e, 1);
  mpz_divexact(e, e, q);

  /* n = p-2 = |2, 3, ... p-1| */
  mpz_init_set(n, p);
  mpz_sub_ui(n, n, 2);

  while(1)
    {
      bignum_random(g, r, n);
      mpz_add_ui(g, g, 2);

      mpz_powm(g, g, e, p);
      if (mpz_cmp_ui(g, 1))
	{
	  /* g != 1. Finished. */
	  mpz_clear(e);
	  mpz_clear(n);

	  return;
	}
    }
}

