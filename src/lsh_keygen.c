/* lsh_keygen.c
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

#include "crypto.h"
#include "format.h"
#include "publickey_crypto.h"
#include "randomness.h"

#include "getopt.h"

#include <stdio.h>

static void usage(void) NORETURN;

static void usage(void)
{
  fprintf(stderr, "Usage: lsh_keygen nist-level\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int l;
  struct dss_public public;
  mpz_t x;
  
  mpz_t t;
  struct randomness *r;
  
  if (argc != 2)
    usage();
  
  l = atoi(argv[1]);

  if ( (l<0) || (l > 8))
    usage();

  mpz_init(public.p);
  mpz_init(public.q);
  mpz_init(public.g);
  mpz_init(public.y);

  mpz_init(x);
  
  mpz_init(t);

  r = make_poor_random(&sha_algorithm, NULL);
  dss_nist_gen(public.p, public.q, r, l);

  mpz_out_str(stderr, 16, public.p);
  printf("\n");
  mpz_out_str(stderr, 16, public.q);
  printf("\n");

  /* Sanity check. */
  if (!mpz_probab_prime_p(q, 10))
    {
      fprintf(stderr, "p not a prime!\n");
      return 1;
    }

  if (!mpz_probab_prime_p(q, 10))
    {
      fprintf(stderr, "p not a prime!\n");
      return 1;
    }

  mpz_fdiv_r(t, p, q);
  if (mpz_cmp_ui(t, 1))
    {
      fprintf(stderr, "q doesn't divide p-1 !\n");
      return 1;
    }

  dss_find_generator(public.g, r, public.p, public.q);

  r = make_reasonably_random();
  mpz_set(t, q);
  mpz_sub_ui(t, t, 2);
  bignum_random(x, r, t);

  mpz_add_ui(x, x, 1);
  
  /* Now, output a private key spki structure. */
  struct sexp *key =
    sexp_l(2, sexp_z("private-key"),
	   sexp_l(6, sexp_z("dss")
		  sexp_l(2, sexp_z("p"), sexp_n(public.p), -1),
		  sexp_l(2, sexp_z("q"), sexp_n(public.q), -1),
		  sexp_l(2, sexp_z("g"), sexp_n(public.g), -1),
		  sexp_l(2, sexp_z("y"), sexp_n(public.y), -1),
		  sexp_l(2, sexp_z("p"), sexp_n(x), -1), -1), -2);

  
  return 0;
}

  
