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
#include "xalloc.h"

#include "lsh_argp.h"

#include <stdio.h>
#include <stdlib.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "lsh_keygen.c.x"

/* Option parsing */

/* GABA:
   (class
     (name lsh_keygen_options)
     (vars
       (style . sexp_argp_state)
       ; (algorithm . int)
       (level . int)))
*/

static struct lsh_keygen_options *
make_lsh_keygen_options(void)
{
  NEW(lsh_keygen_options, self);
  self->style = SEXP_TRANSPORT;
  self->level = 8;

  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "algorithm", 'a', "Algorithm", 0, "Default is to generate dsa keys", 0 },
  { "nist-level", 'l', "Security level", 0, "Level 0 uses 512-bit primes, "
    "level 8 uses 1024 bit primes. Default is 8.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
main_argp_children[] =
{
  { &sexp_output_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg UNUSED, struct argp_state *state)
{
  CAST(lsh_keygen_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->style;
      state->child_inputs[1] = NULL;
      break;
    case ARGP_KEY_ARG:
      argp_error(state, "Spurious arguments.");
      break;
    case 'l':
	{
	  char *end;
	  long l = strtol(optarg, &end, 0);
	      
	  if (!*arg || *end)
	    {
	      argp_error(state, "Invalid security level.");
	      break;
	    }
	  if ( (l<0) || (l > 8))
	    {
	      argp_error(state, "Security level should be in the range 0-8.");
	      break;
	    }
	  self->level = l;
	  break;
	}

    case 'a':
      if (strcmp(arg, "dsa"))
	argp_error(state, "Sorry, doesn't support any algorithm but dsa.");

      break;
      
    }
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  "[-l LEVEL] [-a dsa]",
  ( "Generates a new private key for the given algorithm and security level.\v"
    "You will usually want to pipe the new key into a program like lsh_writekey, "
    "to split it into its private and public parts, and optionally encrypt "
    "the private information."),
  main_argp_children,
  NULL, NULL
};


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
  struct lsh_keygen_options * options
    = make_lsh_keygen_options();
  
  struct dsa_public public;
  mpz_t x;
  
  mpz_t t;
  struct randomness *r;

  argp_parse(&main_argp, argc, argv, 0, NULL, options);
  
  mpz_init(public.p);
  mpz_init(public.q);
  mpz_init(public.g);
  mpz_init(public.y);

  mpz_init(x);
  
  mpz_init(t);

  r = make_poor_random(&sha1_algorithm, NULL);
  dsa_nist_gen(public.p, public.q, r, options->level);

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
      fatal("q doesn't divide p-1 !\n");
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
       options->style, 0);

    A_WRITE(output, key);

    return EXIT_SUCCESS;
  }
}

  
