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

#include "format.h"
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

/* FIXME: Fold directly into the lsh-keygen program. */
struct lsh_string *
rsa_generate_key(struct randomness *r, UINT32 bits)
{
  struct rsa_public_key public;
  struct rsa_private_key private;
  struct lsh_string *key = NULL;

  rsa_public_key_init(&public);
  rsa_private_key_init(&private);

  assert(r->quality == RANDOM_GOOD);
  
  if (rsa_generate_keypair(&public, &private,
			   r, lsh_random,
			   NULL, progress,
			   bits, E_SIZE))
    {
      key = lsh_sexp_format(0, "(%0s(%0s(%0s%b)(%0s%b)"
			    "(%0s%b)(%0s%b)(%0s%b)(%0s%b)(%0s%b)(%0s%b)))",
			    "private-key", "rsa-pkcs1",
			    "n", public.n,
			    "e", public.e,
			    "d", private.d,
			    "p", private.p,
			    "q", private.q,
			    "a", private.a,
			    "b", private.b,
			    "c", private.c);
    }
  rsa_public_key_clear(&public);
  rsa_private_key_clear(&private);
  return key;
}

