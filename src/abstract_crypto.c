/* abstract_io.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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

#include "abstract_crypto.h"

#include "crypto.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#define CLASS_DEFINE
#include "abstract_crypto.h.x"
#undef CLASS_DEFINE

#include "abstract_crypto.c.x"

/* Combining block cryptos */

/* Inverts the encryption mode (needed for the EDE-operation of
 * triple DES). */
/* CLASS:
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

/* XOR:s src onto dst */
/* NOTE: Perhaps it would make sense to optimize this function. */
void memxor(UINT8 *dst, const UINT8 *src, size_t n)
{
  size_t i;
  for (i = 0; i<n; i++)
    dst[i] ^= src[i];
}

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
  
  while (1)
    {
      /* During this loop, x is always odd */
      UINT32 d;

      assert(x % 2);
      
      if (!y)
	return x * res;
      
      while (!(y % 2))
	y /= 2;
      
      d = x-y;

      if (d<0)
	{ /* x < y */
	  y = - d;
	}
      else
	{ /* x >= y */
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

