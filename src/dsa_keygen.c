/* dsa_keygen.c
 *
 * Generate dsa key pairs..
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "dsa.h"

#include "randomness.h"
#include "sexp.h"
#include "werror.h"

#include "nettle/dsa.h"

#include <assert.h>


#define SA(x) sexp_a(ATOM_##x)

/* FIXME: Let caller supply the progress function. */

static void
progress(void *ctx UNUSED, int c)
{
  char buf[2];
  buf[0] = c; buf[1] = '\0';
  if (c != 'e')
    werror_progress(buf);
}

struct sexp *
dsa_generate_key(struct randomness *r, unsigned level)
{
  struct dsa_public_key public;
  struct dsa_private_key private;
  struct sexp *key = NULL;

  dsa_public_key_init(&public);
  dsa_private_key_init(&private);

  assert(r->quality == RANDOM_GOOD);
  
  if (dsa_generate_keypair(&public, &private,
			   r, lsh_random,
			   NULL, progress,
			   512 + 64 * level))
    {
      key = sexp_l(2, SA(PRIVATE_KEY),
		   sexp_l(6, SA(DSA),
			  sexp_l(2, SA(P), sexp_un(public.p), -1),
			  sexp_l(2, SA(Q), sexp_un(public.q), -1),
			  sexp_l(2, SA(G), sexp_un(public.g), -1),
			  sexp_l(2, SA(Y), sexp_un(public.y), -1),
			  sexp_l(2, SA(X), sexp_un(private.x), -1), -1), -1);
    }

  dsa_public_key_clear(&public);
  dsa_private_key_clear(&private);
  return key;
}
