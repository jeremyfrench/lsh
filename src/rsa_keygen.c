/* rsa_keygen.c
 *
 * Generate rsa key pairs.
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#include "publickey_crypto.h"

#include "randomness.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/rsa.h"

#include <assert.h>

#define SA(x) sexp_a(ATOM_##x)


static void
progress(void *ctx UNUSED, int c)
{
  char buf[2];
  buf[0] = c; buf[1] = '\0';
  if (c != 'e')
    werror_progress(buf);
}

/* Uses a 30-bit e. */
#define E_SIZE 30
struct sexp *
rsa_generate_key(struct randomness *r, UINT32 bits)
{
  struct rsa_public_key public;
  struct rsa_private_key private;
  struct sexp *key = NULL;

  rsa_init_public_key(&public);
  rsa_init_private_key(&private);

  assert(r->quality == RANDOM_GOOD);
  
  if (rsa_generate_keypair(&public, &private,
			   r, lsh_random,
			   NULL, progress,
			   bits, E_SIZE))
    {
      key = sexp_l(2, SA(PRIVATE_KEY),
		   sexp_l(9, SA(RSA_PKCS1),
			  sexp_l(2, SA(N), sexp_un(public.n), -1),
			  sexp_l(2, SA(E), sexp_un(public.e), -1),
			  sexp_l(2, SA(D), sexp_un(private.d), -1),
			  sexp_l(2, SA(P), sexp_un(private.p), -1),
			  sexp_l(2, SA(Q), sexp_un(private.q), -1),
			  sexp_l(2, SA(A), sexp_un(private.a), -1),
			  sexp_l(2, SA(B), sexp_un(private.b), -1),
			  sexp_l(2, SA(C), sexp_un(private.c), -1), -1), -1);
    }
  rsa_clear_public_key(&public);
  rsa_clear_private_key(&private);
  return key;
}

