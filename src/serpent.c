/* serpent.c
 *
 * $Id$ */
/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2000 Niels Möller, Rafael R. Sevilla
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

#include "werror.h"
#include "xalloc.h"
#include "serpent.h"
#include <assert.h>
#include "serpent.c.x"

/* Serpent */
/* GABA:
   (class
     (name serpent_instance)
     (super crypto_instance)
     (vars
       (ctx . "SERPENT_context")))
*/

static void do_serpent_encrypt(struct crypto_instance *s,
			       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(serpent_instance, self, s);

  FOR_BLOCKS(length, src, dst, SERPENT_BLOCKSIZE)
    serpent_encrypt(&self->ctx, src, dst);
}

static void do_serpent_decrypt(struct crypto_instance *s,
			       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(serpent_instance, self, s);

  FOR_BLOCKS(length, src, dst, SERPENT_BLOCKSIZE)
    serpent_decrypt(&self->ctx, src, dst);
}

static struct crypto_instance *
make_serpent_instance(struct crypto_algorithm *algorithm, int mode,
		      const UINT8 *key, const UINT8 *iv UNUSED)
{
  NEW(serpent_instance, self);

  self->super.block_size = SERPENT_BLOCKSIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_serpent_encrypt
			: do_serpent_decrypt);

  /* We don't have to deal with weak keys - as a second round AES candidate,
     Serpent doesn't have any, but it can only use 256 bit keys so we do
     an assertion check. */
  assert(algorithm->key_size == SERPENT_KEYSIZE);
  serpent_setup(&self->ctx, key);

  return(&self->super);
}

struct crypto_algorithm *
make_serpent_algorithm(UINT32 key_size)
{
  NEW(crypto_algorithm, algorithm);

  assert(key_size == SERPENT_KEYSIZE);

  algorithm->block_size = SERPENT_BLOCKSIZE;
  algorithm->key_size = key_size;
  algorithm->iv_size = 0;
  algorithm->make_crypt = make_serpent_instance;

  return algorithm;
}

struct crypto_algorithm *make_serpent(void)
{
  return(make_serpent_algorithm(SERPENT_KEYSIZE));
}
