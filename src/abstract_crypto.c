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

/* CLASS:
   (class
     (name cbc_algorithm)
     (super crypto_algorithm)
     (vars
       (inner object crypto_algorithm)))
*/

/* CLASS:
   (class
     (name cbc_instance)
     (super crypto_instance)
     (vars
       (inner object crypto_instance)
       (iv space UINT8)))
*/
		    
static void do_cbc_encrypt(struct crypto_instance *s,
			   UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(cbc_instance, self, s);
  
  FOR_BLOCKS(length, src, dst, self->super.block_size)
    {
      memxor(self->iv, src, self->super.block_size);

      CRYPT(self->inner, self->super.block_size, src, self->iv);

      memcpy(dst, self->iv, self->super.block_size);
    }
}

static void do_cbc_decrypt(struct crypto_instance *s,
			   UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(cbc_instance, self, s);
  
  if (length % self->super.block_size)
    fatal("Internal error\n");

  if (!length)
    return;

  /* Decrypt in ECB mode */
  CRYPT(self->inner, length, src, dst);

  /* XOR the cryptotext, shifted one block */
  memxor(dst,
	 self->iv, self->super.block_size);
  memxor(dst + self->super.block_size,
	 src, length - self->super.block_size);
  memcpy(self->iv,
	 src + length - self->super.block_size, self->super.block_size);
}

static struct crypto_instance *
do_make_cbc_instance(struct crypto_algorithm *s,
		     int mode, const UINT8 *key, const UINT8 *iv)
{
  CAST(cbc_algorithm, algorithm, s);
  NEW(cbc_instance, instance);

  instance->super.block_size = algorithm->super.block_size;

  /* NOTE: We use a prefix of the iv, and pass the tail on to the
   * inner block crypto. This allows nested chaining, although the
   * semantics may be a little obscure.. */
  instance->inner = MAKE_CRYPT(algorithm->inner, mode, key,
			       iv + algorithm->super.block_size);
  if (!instance->inner)
    {
      /* Weak key */
      KILL(instance);
      return NULL;
    }
  instance->iv = lsh_space_alloc(algorithm->super.block_size);
  memcpy(instance->iv, iv, algorithm->super.block_size);

  instance->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			    ? do_cbc_encrypt
			    : do_cbc_decrypt);
  return &instance->super;
}

struct crypto_algorithm *crypto_cbc(struct crypto_algorithm *inner)
{
  NEW(cbc_algorithm, algorithm);
  algorithm->super.block_size = inner->block_size;
  algorithm->super.key_size = inner->key_size;
  algorithm->super.iv_size = inner->iv_size + inner->block_size;

  algorithm->inner = inner;
  algorithm->super.make_crypt = do_make_cbc_instance;

  return &algorithm->super;
} 

/* Inverts the encryption mode (needed for the EDE-operation of
 * tripple DES). */
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

/* CLASS:
   (class
     (name crypto_cascade_algorithm)
     (super crypto_algorithm)
     (vars
       (cascade object object_list)))
*/

/* CLASS:
   (class
     (name crypto_cascade_instance)
     (super crypto_instance)
     (vars
       (cascade object object_list)))
*/     
       
static void do_cascade_crypt(struct crypto_instance *s,
			     UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(crypto_cascade_instance, self, s);
  unsigned i;
  
  if (length % self->super.block_size)
    fatal("Internal error!\n");

  assert(LIST_LENGTH(self->cascade));

  {
    CAST_SUBTYPE(crypto_instance, o, LIST(self->cascade)[0]);
    CRYPT(o, length, src, dst);
  }
  for (i = 1; i<LIST_LENGTH(self->cascade); i++)
    {
      CAST_SUBTYPE(crypto_instance, o, LIST(self->cascade)[i]);
      CRYPT(o, length, dst, dst);
    }
}

static struct crypto_instance *
do_make_cascade(struct crypto_algorithm *s,
		int mode, const UINT8 *key, const UINT8 *iv)
{
  CAST(crypto_cascade_algorithm, algorithm, s);
  NEW(crypto_cascade_instance, instance);
  unsigned i;
  
  instance->super.block_size = algorithm->super.block_size;
  instance->cascade = alloc_object_list(LIST_LENGTH(algorithm->cascade));

  /* FIXME: When decrypting, the crypto algorithm should be used in
   * reverse order! */
  for (i = 0; i<LIST_LENGTH(algorithm->cascade); i++)
    {
      CAST_SUBTYPE(crypto_algorithm, a, LIST(algorithm->cascade)[i]);
      struct crypto_instance *o	= MAKE_CRYPT(a, mode, key, iv);
      
      if (!o)
	{
	  KILL(instance);
	  return NULL;
	}

      LIST(instance->cascade)[i] = (struct lsh_object *) o;
      key += a->key_size;
      iv += a->iv_size;
    }

  instance->super.crypt = do_cascade_crypt;
  
  return &instance->super;
}

struct crypto_algorithm *crypto_cascadel(struct object_list *cascade)
{
  NEW(crypto_cascade_algorithm, self);
  unsigned i;
  
  self->cascade = cascade;

  self->super.key_size = self->super.iv_size = 0;
  self->super.block_size = 1;

  for (i = 0; i<LIST_LENGTH(self->cascade); i++)
    {
      CAST_SUBTYPE(crypto_algorithm, a, LIST(self->cascade)[i]);
      self->super.key_size += a->key_size;
      self->super.iv_size += a->iv_size;
      self->super.block_size = lcm(self->super.block_size, a->block_size);
    }

  self->super.make_crypt = do_make_cascade;

  return &self->super;
} 

struct crypto_algorithm *crypto_cascade(unsigned n, ...)
{
  va_list args;
  struct object_list *l;

  va_start(args, n);
  l = make_object_listv(n, args);
  va_end(args);

  return crypto_cascadel(l);
}

/* The HMAC (rfc-2104)  construction */
/* CLASS:
   (class
     (name hmac_algorithm)
     (super mac_algorithm)
     (vars
       (hash object hash_algorithm)))
*/

/* CLASS:
   (class
     (name hmac_instance)
     (super mac_instance)
     (vars
       ; Initialized hash objects 
       (hinner object hash_instance)
       (houter object hash_instance)

       ; Modified by update 
       (state object hash_instance)))
*/

static void do_hmac_update(struct mac_instance *s,
			   UINT32 length, UINT8 *data)
{
  CAST(hmac_instance, self, s);

  HASH_UPDATE(self->state, length, data);
}

static void do_hmac_digest(struct mac_instance *s,
			   UINT8 *data)
{
  CAST(hmac_instance, self, s);
  struct hash_instance *h = self->state;

  HASH_DIGEST(h, data);   /* Inner hash */
  KILL(h);
  h = HASH_COPY(self->houter);
  HASH_UPDATE(h, self->super.mac_size, data);
  HASH_DIGEST(h, data);
  KILL(h);

  self->state = HASH_COPY(self->hinner);
}

static struct mac_instance *do_hmac_copy(struct mac_instance *s)
{
  CAST(hmac_instance, self, s);
  CLONED(hmac_instance, new, self);

  new->state = HASH_COPY(self->state);

  return &new->super;
}

#define IPAD 0x36
#define OPAD 0x5c

static struct mac_instance *make_hmac_instance(struct mac_algorithm *s,
					       const UINT8 *key)
{
  CAST(hmac_algorithm, self, s);
  NEW(hmac_instance, instance);
  UINT8 *pad = alloca(self->hash->block_size);

  instance->super.hash_size = self->super.hash_size;
  instance->super.update = do_hmac_update;
  instance->super.digest = do_hmac_digest;
  instance->super.copy = do_hmac_copy;

  instance->hinner = MAKE_HASH(self->hash);

  memset(pad, IPAD, self->hash->block_size);
  memxor(pad, key, self->hash->hash_size);

  HASH_UPDATE(instance->hinner, self->hash->block_size, pad);

  instance->houter = MAKE_HASH(self->hash);

  memset(pad, OPAD, self->hash->block_size);
  memxor(pad, key, self->hash->block_size);
  
  HASH_UPDATE(instance->houter, self->hash->block_size, pad);

  instance->state = HASH_COPY(instance->hinner);

  return &instance->super;
} 
  
struct mac_algorithm *make_hmac_algorithm(struct hash_algorithm *h)
{
  NEW(hmac_algorithm, self);

  self->super.hash_size = h->hash_size;
  /* Recommended in RFC-2104 */
  self->super.key_size = h->hash_size;
  self->super.make_mac = make_hmac_instance;

  self->hash = h;

  return &self->super;
}


/* XOR:s src onto dst */
/* FIXME: Perhaps it would make sense to optimize this function. */
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

