/* pkcs5.c
 *
 * PKCS#5 "PBKDF2" style key derivation.
 *
 * $Id$ */

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

#include "crypto.h"

#include "memxor.h"
#include "xalloc.h"

#include <assert.h>

void
pkcs5_key_derivation(struct mac_algorithm *prf,
		     UINT32 password_length, UINT8 *password,
		     UINT32 salt_length, UINT8 *salt,
		     UINT32 iterations,
		     UINT32 key_length, UINT8 *key)
{
  struct mac_instance *m = MAKE_MAC(prf, password_length, password);
  UINT32 left = key_length;

  /* Set up the block counter buffer. This will never have more than
   * the last few bits set (using sha1, 8 bits = 5100 bytes of key) so
   * we only change the last byte. */

  UINT8 block_count[4] = { 0, 0, 0, 1 }; 

  UINT8 *digest = alloca(prf->hash_size);
  UINT8 *buffer = alloca(prf->hash_size);

  assert(iterations);
  assert(key_length <= 255 * prf->hash_size);
  
  for (;; block_count[3]++)
    {
      UINT32 i;
      assert(block_count[3]);
      
      /* First iterate */
      HASH_UPDATE(m, salt_length, salt);
      HASH_UPDATE(m, 4, block_count);
      HASH_DIGEST(m, buffer);

      for (i = 1; i < iterations; i++)
	{
	  HASH_UPDATE(m, prf->hash_size, buffer);
	  HASH_DIGEST(m, digest);
	  memxor(buffer, digest, prf->hash_size);
	}

      if (left <= prf->hash_size)
	{
	  memcpy(key, buffer, left);
	  break;
	}
      else
	{
	  memcpy(key, buffer, prf->hash_size);
	  key += prf->hash_size;
	  left -= prf->hash_size;
	}
    }
  KILL(m);
}
