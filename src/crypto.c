/* crypto.c
 *
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "crypto.h"
#include "werror.h"
#include "xalloc.h"

#include "blowfish.h"
#include "des.h"
#include "rc4.h"
#include "sha.h"
#include "md5.h"

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "crypto.c.x"

/* CLASS:
   (class
     (name rc4_instance)
     (super crypto_instance)
     (vars
       (ctx simple "struct rc4_ctx")))
*/
   
static void do_crypt_rc4(struct crypto_instance *s,
			 UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(rc4_instance, self, s);

  if (length % 8)
    fatal("Internal error\n");

  rc4_crypt(&self->ctx, dst, src, length);
}

static struct crypto_instance *
make_rc4_instance(struct crypto_algorithm *ignored UNUSED, int mode,
		  const UINT8 *key, const UINT8 *iv UNUSED)
{
  NEW(rc4_instance, self);

  self->super.block_size = 8;
  self->super.crypt = do_crypt_rc4;

  rc4_set_key(&self->ctx, key, 16);

  return &self->super;
}

struct crypto_algorithm crypto_rc4_algorithm =
{ STATIC_HEADER,
  8, 16, 0, make_rc4_instance };
  

/* Blowfish */
/* CLASS:
   (class
     (name blowfish_instance)
     (super crypto_instance)
     (vars
       (ctx simple "BLOWFISH_context")))
*/

static void do_blowfish_encrypt(struct crypto_instance *s,
				UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(blowfish_instance, self, s);

  FOR_BLOCKS(length, src, dst, BLOWFISH_BLOCKSIZE)
    bf_encrypt_block(&self->ctx, dst, src);
}

static void do_blowfish_decrypt(struct crypto_instance *s,
				UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(blowfish_instance, self, s);

  FOR_BLOCKS(length, src, dst, BLOWFISH_BLOCKSIZE)
    bf_decrypt_block(&self->ctx, dst, src);
}

static struct crypto_instance *
make_blowfish_instance(struct crypto_algorithm *algorithm, int mode, 
		       const UINT8 *key, const UINT8 *iv UNUSED)
{
  NEW(blowfish_instance, self);

  self->super.block_size = BLOWFISH_BLOCKSIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_blowfish_encrypt
			: do_blowfish_decrypt);
  
  switch (bf_set_key(&self->ctx, key, algorithm->key_size))
    {
    case 0:
      return &self->super;
    default:
      werror("Detected a weak blowfish key!\n");
      KILL(self);
      return NULL;
    }
}

struct crypto_algorithm *make_blowfish_algorithm(UINT32 key_size)
{
  NEW(crypto_algorithm, algorithm);

  assert(key_size <= BLOWFISH_MAX_KEYSIZE);
  assert(key_size >= BLOWFISH_MIN_KEYSIZE);
  
  algorithm->block_size = BLOWFISH_BLOCKSIZE;
  algorithm->key_size = key_size;
  algorithm->iv_size = 0;
  algorithm->make_crypt = make_blowfish_instance;

  return algorithm;
}

struct crypto_algorithm *make_blowfish(void)
{
  return make_blowfish_algorithm(BLOWFISH_KEYSIZE);
}

/* CLASS:
   (class
     (name des_instance)
     (super crypto_instance)
     (vars
       (ctx array (simple UINT32) DES_EXPANDED_KEYLEN)))
*/

static void do_des_encrypt(struct crypto_instance *s,
			   UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(des_instance, self, s);

  FOR_BLOCKS(length, src, dst, DES_BLOCKSIZE)
    DesSmallFipsEncrypt(dst, self->ctx, src);
}

static void do_des_decrypt(struct crypto_instance *s,
			 UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(des_instance, self, s);

  FOR_BLOCKS(length, src, dst, DES_BLOCKSIZE)
    DesSmallFipsDecrypt(dst, self->ctx, src);
}

static struct crypto_instance *
make_des_instance(struct crypto_algorithm *algorithm, int mode, 
		  const UINT8 *key, const UINT8 *iv UNUSED)
{
  NEW(des_instance, self);
  UINT8 pkey[DES_KEYSIZE];
  unsigned i;

  /* Fix parity */
  for (i=0; i<DES_KEYSIZE; i++)
    {
      UINT8 p = key[i];
      p ^= (p >> 4);
      p ^= (p >> 2);
      p ^= (p >> 1);
      pkey[i] = key[i] ^ (p & 1);
    }

  self->super.block_size = DES_BLOCKSIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_des_encrypt
			: do_des_decrypt);
  
  switch (DesMethod(self->ctx, pkey))
    {
    case 0:
      return &self->super;
    case -1:
      fatal("Internal error! Bad parity in make_des_instance.\n");
    case -2:
      werror("Detected weak DES key.\n");
      KILL(self);
      return NULL;
    default:
      fatal("Internal error!\n");
    }
}

struct crypto_algorithm crypto_des_algorithm =
{ STATIC_HEADER,
  DES_BLOCKSIZE, DES_KEYSIZE, 0, make_des_instance };

struct crypto_algorithm *make_des3(void)
{
  return crypto_cascade(3,
			&crypto_des_algorithm,
			crypto_invert(&crypto_des_algorithm),
			&crypto_des_algorithm,
			-1);
}

/* SHA1 hash */
/* CLASS:
   (class
     (name sha_instance)
     (super hash_instance)
     (vars
       (ctx simple "struct sha_ctx")))
*/

static void do_sha_update(struct hash_instance *s,
			  UINT32 length, UINT8 *data)
{
  CAST(sha_instance, self, s);

  sha_update(&self->ctx, data, length);
}

static void do_sha_digest(struct hash_instance *s,
			  UINT8 *dst)
{
  CAST(sha_instance, self, s);

  sha_final(&self->ctx);
  sha_digest(&self->ctx, dst);
  sha_init(&self->ctx);
}

static struct hash_instance *do_sha_copy(struct hash_instance *s)
{
  return &CLONE(sha_instance, s)->super;
}

static struct hash_instance *
make_sha_instance(struct hash_algorithm *ignored UNUSED)
{
  NEW(sha_instance, res);

  res->super.hash_size = 20;
  res->super.update = do_sha_update;
  res->super.digest = do_sha_digest;
  res->super.copy = do_sha_copy;

  sha_init(&res->ctx);

  return &res->super;
}

struct hash_algorithm sha_algorithm =
{ STATIC_HEADER,
  SHA_DATASIZE, SHA_DIGESTSIZE, make_sha_instance };


/* MD5 hash */
/* CLASS:
   (class
     (name md5_instance)
     (super hash_instance)
     (vars
       (ctx simple "struct md5_ctx")))
*/

static void do_md5_update(struct hash_instance *s,
			  UINT32 length, UINT8 *data)
{
  CAST(md5_instance, self, s);

  md5_update(&self->ctx, data, length);
}

static void do_md5_digest(struct hash_instance *s,
			  UINT8 *dst)
{
  CAST(md5_instance, self, s);

  md5_final(&self->ctx);
  md5_digest(&self->ctx, dst);
  md5_init(&self->ctx);
}

static struct hash_instance *do_md5_copy(struct hash_instance *s)
{
  return &CLONE(md5_instance, s)->super;
}

static struct hash_instance *
make_md5_instance(struct hash_algorithm *ignored UNUSED)
{
  NEW(md5_instance, res);

  res->super.hash_size = 16;
  res->super.update = do_md5_update;
  res->super.digest = do_md5_digest;
  res->super.copy = do_md5_copy;

  md5_init(&res->ctx);

  return &res->super;
}

struct hash_algorithm md5_algorithm =
{ STATIC_HEADER,
  MD5_DATASIZE, MD5_DIGESTSIZE, make_md5_instance };

