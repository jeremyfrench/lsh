/* dsa_keygen.c
 *
 * Generate dsa key pairs..
 *
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

#include "publickey_crypto.h"

#include "format.h"
#include "randomness.h"
#include "sexp.h"
#include "werror.h"

#include "nettle/dsa.h"

#include <assert.h>


/* FIXME: Let caller supply the progress function. */

static void
progress(void *ctx UNUSED, int c)
{
  char buf[2];
  buf[0] = c; buf[1] = '\0';
  if (c != 'e')
    werror_progress(buf);
}

/* FIXME: Fold directly into the lsh-keygen program. */
struct lsh_string *
dsa_generate_key(struct randomness *r, unsigned level)
{
  struct dsa_public_key public;
  struct dsa_private_key private;
  struct lsh_string *key = NULL;

  dsa_public_key_init(&public);
  dsa_private_key_init(&private);

  assert(r->quality == RANDOM_GOOD);
  
  if (dsa_generate_keypair(&public, &private,
			   r, lsh_random,
			   NULL, progress,
			   512 + 64 * level))
    {
      key = lsh_sexp_format(0, "(private-key(dsa(p%b)(q%b)(g%b)(y%b)(x%b)))",
			    public.p, public.q, public.g, public.y,
			    private.x);
    }

  dsa_public_key_clear(&public);
  dsa_private_key_clear(&private);
  return key;
}
