/* lsh_keygen.c
 *
 * Generic key-generation program. Writes a spki-packaged private key
 * on stdout. You would usually pipe this to some other program to
 * extract the public key, encrypt the private key, and save the
 * results in two separate files.
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

#include "dsa_keygen.h"

#include "blocking_write.h"
#include "crypto.h"
#include "format.h"
#include "publickey_crypto.h"
#include "randomness.h"
#include "sexp.h"
#include "werror.h"

#include "getopt.h"

#include <stdio.h>
#include <stdlib.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

static void usage(void) NORETURN;

static void usage(void)
{
  werror("Usage: lsh_keygen [-o style] [-l nist-level] [-a dsa] [-q] [-d] [-v]\n");
  exit(1);
}

static void
do_lsh_keygen_handler(struct exception_handler *s UNUSED,
		      const struct exception *e)
{
  werror("lsh_keygen: %z\n", e->msg);

  exit(EXIT_FAILURE);
}

static struct exception_handler handler =
STATIC_EXCEPTION_HANDLER(do_lsh_keygen_handler, NULL);

int main(int argc, char **argv)
{
  int option;
  long l = 4;
  int style = SEXP_TRANSPORT;
  
  struct dsa_public public;
  mpz_t x;
  
  mpz_t t;
  struct randomness *r;

  while((option = getopt(argc, argv, "a:dl:o:qv")) != -1)
    switch(option)
      {
      case 'l':
	{
	  char *end;

	  l = strtol(optarg, &end, 0);
	      
	  if (!*optarg || *end)
	    usage();

	  if ( (l<0) || (l > 8))
	    {
	      werror("lsh_keygen: nist-level should be in the range 0-8.\n");
	      usage();
	    }
	  break;
	}
      case 'a':
	if (strcmp(optarg, "dsa"))
	  {
	    werror("lsh_keygen: Sorry, doesn't support any algorithm but dsa.\n");
	    usage();
	  }
	break;
      case 'o':
	if (!strcmp(optarg, "transport"))
	  style = SEXP_TRANSPORT;
	else if (!strcmp(optarg, "canonical"))
	  style = SEXP_CANONICAL;
	else if (!strcmp(optarg, "advanced"))
	  style = SEXP_ADVANCED;
	else if (!strcmp(optarg, "international"))
	  style = SEXP_INTERNATIONAL;
	else
	  {
	    werror("lsh_keygen: Style must be one of\n"
		   "  'transport', 'canonical', 'advanced' or 'international'\n");
	    usage();
	  }
	break;
      case 'q':
	quiet_flag = 1;
	break;
      case 'd':
	debug_flag = 1;
	break;
      case 'v':
	verbose_flag = 1;
	break;
      default:
	usage();
      }
  
  if (argc != optind)
    usage();
  
  mpz_init(public.p);
  mpz_init(public.q);
  mpz_init(public.g);
  mpz_init(public.y);

  mpz_init(x);
  
  mpz_init(t);

  r = make_poor_random(&sha_algorithm, NULL);
  dsa_nist_gen(public.p, public.q, r, l);

  debug("%xn\n"
	"%xn\n", public.p, public.q);

  /* Sanity check. */
  if (!mpz_probab_prime_p(public.p, 10))
    {
      werror("p not a prime!\n");
      return 1;
    }

  if (!mpz_probab_prime_p(public.q, 10))
    {
      werror("q not a prime!\n");
      return 1;
    }

  mpz_fdiv_r(t, public.p, public.q);
  if (mpz_cmp_ui(t, 1))
    {
      werror("q doesn't divide p-1 !\n");
      return 1;
    }

  dsa_find_generator(public.g, r, public.p, public.q);

  r = make_reasonably_random();
  mpz_set(t, public.q);
  mpz_sub_ui(t, t, 2);
  bignum_random(x, r, t);

  mpz_add_ui(x, x, 1);

  mpz_powm(public.y, public.g, x, public.p);
  
  {
    /* Now, output a private key spki structure. */
    struct abstract_write *output = make_blocking_write(STDOUT_FILENO, 0, &handler);
    
    struct lsh_string *key = sexp_format
      (sexp_l(2, sexp_z("private-key"),
	      sexp_l(6, sexp_z("dsa"),
		     sexp_l(2, sexp_z("p"), sexp_un(public.p), -1),
		     sexp_l(2, sexp_z("q"), sexp_un(public.q), -1),
		     sexp_l(2, sexp_z("g"), sexp_un(public.g), -1),
		     sexp_l(2, sexp_z("y"), sexp_un(public.y), -1),
		     sexp_l(2, sexp_z("x"), sexp_un(x), -1), -1), -1),
       style, 0);

    A_WRITE(output, key);

    return EXIT_SUCCESS;
  }
}

  
