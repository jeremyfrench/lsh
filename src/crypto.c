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

#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "crypto.h"
#include "sha.h"
#include "rc4.h"
#include "werror.h"
#include "xalloc.h"

#include "crypto.c.x"

/* CLASS:
   (class
     (name rc4_instance)
     (super crypto_instance)
     (vars
       (ctx simple "struct rc4_ctx")))
*/
   
static void do_crypt_rc4(struct crypto_instance *s,
			 UINT32 length, UINT8 *src, UINT8 *dst)
{
  CAST(rc4_instance, self, s);

  if (length % 8)
    fatal("Internal error\n");

  rc4_crypt(&self->ctx, dst, src, length);
}

static struct crypto_instance *
make_rc4_instance(struct crypto_algorithm *ignored, int mode, UINT8 *key)
{
  NEW(rc4_instance, self);

  self->super.block_size = 8;
  self->super.crypt = do_crypt_rc4;

  rc4_set_key(&self->ctx, key, 16);

  return &self->super;
}

struct crypto_algorithm crypto_rc4_algorithm =
{ STATIC_HEADER,
  8, 16, make_rc4_instance };

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

static struct hash_instance *make_sha_instance(struct hash_algorithm *ignored)
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

/* HMAC (rfc-2104) */
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
					       UINT8 *key)
{
  CAST(hmac_algorithm, self, s);
  NEW(hmac_instance, instance);
  UINT8 *pad = alloca(self->hash->block_size);
  int i;

  instance->super.hash_size = self->super.hash_size;
  instance->super.update = do_hmac_update;
  instance->super.digest = do_hmac_digest;
  instance->super.copy = do_hmac_copy;

  instance->hinner = MAKE_HASH(self->hash);
  memset(pad, IPAD, self->hash->block_size);

  for(i = 0; i<self->hash->hash_size; i++)
    pad[i] ^= key[i];

  HASH_UPDATE(instance->hinner, self->hash->block_size, pad);

  instance->houter = MAKE_HASH(self->hash);
  memset(pad, OPAD, self->hash->block_size);

  for(i = 0; i<self->hash->hash_size; i++)
    pad[i] ^= key[i];

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

