/* abstract_io.c
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

#include "abstract_crypto.h"

#include "crypto.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#define GABA_DEFINE
#include "abstract_crypto.h.x"
#undef GABA_DEFINE

#include "abstract_crypto.c.x"

/* Combining block cryptos */

/* Inverts the encryption mode (needed for the EDE-operation of
 * triple DES). */
/* GABA:
   (class
     (name crypto_inverted)
     (super crypto_algorithm)
     (vars
       (inner object crypto_algorithm)))
*/

static struct crypto_instance *
do_make_inverted(struct crypto_algorithm *s,
		 int mode, const UINT8 *key, const UINT8 *iv)
{
  CAST(crypto_inverted, self, s);

  return MAKE_CRYPT(self->inner, ( (mode == CRYPTO_ENCRYPT)
				   ? CRYPTO_DECRYPT
				   : CRYPTO_ENCRYPT),
		    key, iv);
}

struct crypto_algorithm *crypto_invert(struct crypto_algorithm *inner)
{
  NEW(crypto_inverted, algorithm);

  algorithm->super.block_size = inner->block_size;
  algorithm->super.key_size = inner->key_size;
  algorithm->super.iv_size = inner->iv_size;

  algorithm->inner = inner;
  algorithm->super.make_crypt = do_make_inverted;

  return &algorithm->super;
}


/* FIXME: These functions don't really belong here. */

UINT32 gcd(UINT32 x, UINT32 y)
{
  UINT32 res = 1;

  if (!x)
    return y;
  if (!y)
    return x;
  
  while (! (x%2) && !(y%2) )
    {
      x /= 2; y /= 2; res *= 2;
    }

  if (!(x % 2))
    {
      /* x is even. Swap */
      UINT32 tmp = x;
      x = y;
      y = tmp;
    }
  
  for (;;)
    {
      /* During this loop, x is always odd */
      assert(x % 2);
      
      if (!y)
	return x * res;
      
      while (!(y % 2))
	y /= 2;
      

      if (x < y)
        y -= x;
      else
	{ /* x >= y */
          UINT32 d = x-y;
	  x = y;
	  y = d;
	}
    }
}
	  
UINT32 lcm(UINT32 x, UINT32 y)
{
  UINT32 g = gcd(x, y);

  assert(!(x % g) && ! (y % g));
  
  return x * (y / g);
}

