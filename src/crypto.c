/* crypto.c
 *
 * Encryption classes on top of nettle.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001 Niels Möller
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "nettle/arcfour.h"
#include "nettle/aes.h"
#include "nettle/blowfish.h"
#include "nettle/cast128.h"
#include "nettle/des.h"
#include "nettle/serpent.h"
#include "nettle/twofish.h"

#include "nettle/cbc.h"
#include "nettle/ctr.h"
#include "nettle/hmac.h"

#include "crypto.h"

#include "format.h"
#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "crypto.h.x"
#undef GABA_DEFINE

#include "crypto.c.x"


/* Arcfour/RC4 */
/* GABA:
   (class
     (name arcfour_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct arcfour_ctx")))
*/
   
static void
do_crypt_arcfour(struct crypto_instance *s,
		 uint32_t length,
		 struct lsh_string *dst, uint32_t di,
		 const struct lsh_string *src, uint32_t si)
{
  CAST(arcfour_instance, self, s);

  assert(!(length % 8));

  lsh_string_crypt(dst, di, src, si, length,
		   (nettle_crypt_func *) arcfour_crypt, &self->ctx);
}

static struct crypto_instance *
make_arcfour_instance(struct crypto_algorithm *ignored UNUSED,
		      int mode UNUSED,
		      const uint8_t *key, const uint8_t *iv UNUSED)
{
  NEW(arcfour_instance, self);

  self->super.block_size = 8;
  self->super.crypt = do_crypt_arcfour;

  arcfour_set_key(&self->ctx, 16, key);

  return &self->super;
}

struct crypto_algorithm crypto_arcfour_algorithm =
{ STATIC_HEADER,
  8, 16, 0, make_arcfour_instance };

/* Create a CBC super class? */

/* AES/Rijndael */
/* GABA:
   (class
     (name aes_cbc_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE)")))
*/

static void
do_aes_cbc_encrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(aes_cbc_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 AES_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) aes_encrypt,
			 &self->ctx.ctx);
}

static void
do_aes_cbc_decrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(aes_cbc_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 AES_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) aes_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_aes_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                      const uint8_t *key, const uint8_t *iv)
{
  NEW(aes_cbc_instance, self);

  self->super.block_size = AES_BLOCK_SIZE;

  if (mode == CRYPTO_ENCRYPT)
    {
      self->super.crypt = do_aes_cbc_encrypt;
      aes_set_encrypt_key(&self->ctx.ctx, algorithm->key_size, key);
    }
  else
    {
      self->super.crypt = do_aes_cbc_decrypt;
      aes_set_decrypt_key(&self->ctx.ctx, algorithm->key_size, key);
    }

  CBC_SET_IV(&self->ctx, iv);
  
  return(&self->super);
}

struct crypto_algorithm crypto_aes128_cbc_algorithm =
{ STATIC_HEADER, AES_BLOCK_SIZE, 16, AES_BLOCK_SIZE, make_aes_cbc_instance};

struct crypto_algorithm crypto_aes256_cbc_algorithm =
{ STATIC_HEADER, AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE, make_aes_cbc_instance};

/* GABA:
   (class
     (name aes_ctr_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CTR_CTX(struct aes_ctx, AES_BLOCK_SIZE)")))
*/

static void
do_aes_ctr_crypt(struct crypto_instance *s,
		 uint32_t length,
		 struct lsh_string *dst, uint32_t di,
		 const struct lsh_string *src, uint32_t si)
{
  CAST(aes_ctr_instance, self, s);

  lsh_string_ctr_crypt(dst, di, src, si, length,
		       AES_BLOCK_SIZE, self->ctx.ctr,
		       (nettle_crypt_func *) aes_encrypt,
		       &self->ctx.ctx);
}

static struct crypto_instance *
make_aes_ctr_instance(struct crypto_algorithm *algorithm, int mode UNUSED,
                      const uint8_t *key, const uint8_t *iv)
{
  NEW(aes_ctr_instance, self);

  self->super.block_size = AES_BLOCK_SIZE;

  self->super.crypt = do_aes_ctr_crypt;
  aes_set_encrypt_key(&self->ctx.ctx, algorithm->key_size, key);

  CTR_SET_COUNTER(&self->ctx, iv);
  
  return(&self->super);
}

struct crypto_algorithm crypto_aes128_ctr_algorithm =
{ STATIC_HEADER, AES_BLOCK_SIZE, 16, AES_BLOCK_SIZE, make_aes_ctr_instance};

struct crypto_algorithm crypto_aes256_ctr_algorithm =
{ STATIC_HEADER, AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE, make_aes_ctr_instance};

/* Triple DES */
/* GABA:
   (class
     (name des3_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct des3_ctx, DES3_BLOCK_SIZE)")))
*/

static void
do_des3_encrypt(struct crypto_instance *s,
		uint32_t length,
		struct lsh_string *dst, uint32_t di,
		const struct lsh_string *src, uint32_t si)
{
  CAST(des3_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 DES3_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) des3_encrypt,
			 &self->ctx.ctx);
}

static void
do_des3_decrypt(struct crypto_instance *s,
		uint32_t length,
		struct lsh_string *dst, uint32_t di,
		const struct lsh_string *src, uint32_t si)
{
  CAST(des3_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 DES3_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) des3_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_des3_cbc_instance(struct crypto_algorithm *algorithm UNUSED,
                       int mode,
                       const uint8_t *key, const uint8_t *iv)
{
  NEW(des3_instance, self);

  self->super.block_size = DES3_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_des3_encrypt
			: do_des3_decrypt);

  CBC_SET_IV(&self->ctx, iv);
  
  if (des3_set_key(&self->ctx.ctx, key))
    return(&self->super);
  else
    {
      werror("Detected a weak DES key.\n");
      KILL(self);
      return NULL;
    }
}

struct crypto_algorithm crypto_des3_cbc_algorithm =
{ STATIC_HEADER,
  DES3_BLOCK_SIZE, DES3_KEY_SIZE, DES3_BLOCK_SIZE, make_des3_cbc_instance };


/* Cast-128 */
/* GABA:
   (class
     (name cast128_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct cast128_ctx, CAST128_BLOCK_SIZE)")))
*/

static void
do_cast128_encrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(cast128_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 CAST128_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) cast128_encrypt,
			 &self->ctx.ctx);
}

static void
do_cast128_decrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(cast128_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 CAST128_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) cast128_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_cast128_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                          const uint8_t *key, const uint8_t *iv)
{
  NEW(cast128_instance, self);

  self->super.block_size = CAST128_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_cast128_encrypt
			: do_cast128_decrypt);

  cast128_set_key(&self->ctx.ctx, algorithm->key_size, key);
  CBC_SET_IV(&self->ctx, iv);

  return(&self->super);
}

struct crypto_algorithm crypto_cast128_cbc_algorithm =
{ STATIC_HEADER,
  CAST128_BLOCK_SIZE, CAST128_KEY_SIZE, CAST128_BLOCK_SIZE,
  make_cast128_cbc_instance};


/* Twofish */
/* GABA:
   (class
     (name twofish_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct twofish_ctx, TWOFISH_BLOCK_SIZE)")))
*/

static void
do_twofish_encrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(twofish_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 TWOFISH_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) twofish_encrypt,
			 &self->ctx.ctx);
}

static void
do_twofish_decrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(twofish_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 TWOFISH_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) twofish_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_twofish_cbc_instance(struct crypto_algorithm *algorithm, int mode,
		      const uint8_t *key, const uint8_t *iv)
{
  NEW(twofish_instance, self);

  self->super.block_size = TWOFISH_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_twofish_encrypt
			: do_twofish_decrypt);

  twofish_set_key(&self->ctx.ctx, algorithm->key_size, key);
  CBC_SET_IV(&self->ctx, iv);

  return(&self->super);
}

struct crypto_algorithm crypto_twofish256_cbc_algorithm =
{ STATIC_HEADER,
  TWOFISH_BLOCK_SIZE, 32, TWOFISH_BLOCK_SIZE, make_twofish_cbc_instance};


/* Blowfish */
/* GABA:
   (class
     (name blowfish_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct blowfish_ctx, BLOWFISH_BLOCK_SIZE)")))
*/

static void
do_blowfish_encrypt(struct crypto_instance *s,
		    uint32_t length,
		    struct lsh_string *dst, uint32_t di,
		    const struct lsh_string *src, uint32_t si)
{
  CAST(blowfish_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 BLOWFISH_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) blowfish_encrypt,
			 &self->ctx.ctx);
}

static void
do_blowfish_decrypt(struct crypto_instance *s,
		    uint32_t length,
		    struct lsh_string *dst, uint32_t di,
		    const struct lsh_string *src, uint32_t si)
{
  CAST(blowfish_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 BLOWFISH_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) blowfish_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_blowfish_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                           const uint8_t *key, const uint8_t *iv)
{
  NEW(blowfish_instance, self);

  self->super.block_size = BLOWFISH_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_blowfish_encrypt
			: do_blowfish_decrypt);

  CBC_SET_IV(&self->ctx, iv);

  if (blowfish_set_key(&self->ctx.ctx, algorithm->key_size, key))
    return(&self->super);
  else
    {
      werror("Detected a weak blowfish key!\n");
      KILL(self);
      return NULL;
    }
}

struct crypto_algorithm crypto_blowfish_cbc_algorithm =
{ STATIC_HEADER,
  BLOWFISH_BLOCK_SIZE, BLOWFISH_KEY_SIZE, BLOWFISH_BLOCK_SIZE,
  make_blowfish_cbc_instance};


/* Serpent */
/* GABA:
   (class
     (name serpent_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct serpent_ctx, SERPENT_BLOCK_SIZE)")))
*/

static void
do_serpent_encrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(serpent_instance, self, s);

  lsh_string_cbc_encrypt(dst, di, src, si, length,
			 SERPENT_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) serpent_encrypt,
			 &self->ctx.ctx);
}

static void
do_serpent_decrypt(struct crypto_instance *s,
		   uint32_t length,
		   struct lsh_string *dst, uint32_t di,
		   const struct lsh_string *src, uint32_t si)
{
  CAST(serpent_instance, self, s);

  lsh_string_cbc_decrypt(dst, di, src, si, length,
			 SERPENT_BLOCK_SIZE, self->ctx.iv,
			 (nettle_crypt_func *) serpent_decrypt,
			 &self->ctx.ctx);
}

static struct crypto_instance *
make_serpent_cbc_instance(struct crypto_algorithm *algorithm, int mode,
			  const uint8_t *key, const uint8_t *iv)
{
  NEW(serpent_instance, self);

  self->super.block_size = SERPENT_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_serpent_encrypt
			: do_serpent_decrypt);

  serpent_set_key(&self->ctx.ctx, algorithm->key_size, key);
  CBC_SET_IV(&self->ctx, iv);

  return(&self->super);
}

struct crypto_algorithm crypto_serpent256_cbc_algorithm =
{ STATIC_HEADER,
  SERPENT_BLOCK_SIZE, SERPENT_KEY_SIZE, SERPENT_BLOCK_SIZE,
  make_serpent_cbc_instance};


/* Hashes */

void
hash_update(struct hash_instance *self,
	    uint32_t length, const uint8_t *data)
{
  self->type->update(self->ctx, length, data);
}

struct lsh_string *
hash_digest_string(struct hash_instance *self)
{
  struct lsh_string *s = lsh_string_alloc(self->type->digest_size);
  lsh_string_write_hash(s, 0, self->type, self->ctx);

  return s;
}

#define HASH_INSTANCE_SIZE(type) \
  (offsetof(struct hash_instance, ctx) + type->context_size)

struct hash_instance *
hash_copy(struct hash_instance *self)
{
  CLONED_VAR_OBJECT(hash_instance, copy, self,
		    HASH_INSTANCE_SIZE(self->type));

  return copy;
}

struct hash_instance *
make_hash(const struct nettle_hash *algorithm)
{
  NEW_VAR_OBJECT(hash_instance, instance,
		 HASH_INSTANCE_SIZE(algorithm));

  instance->type = algorithm;
  algorithm->init(instance->ctx);

  return instance;
}

/* HMAC */

/* GABA:
   (class
     (name hmac_instance)
     (super mac_instance)
     (vars
       (type . "const struct nettle_hash *")
       (ctx var-array char)))
*/

#define HMAC_OUTER(self) ((self)->ctx)
#define HMAC_INNER(self) ((self)->ctx + (self)->type->context_size)
#define HMAC_STATE(self) ((self)->ctx + 2 * (self)->type->context_size)

#define HMAC_SIZE(type) \
  (offsetof(struct hmac_instance, ctx) + 3 * type->context_size)

static void
do_hmac_update(struct mac_instance *s,
	       uint32_t length, const uint8_t *data)
{
  CAST(hmac_instance, self, s);
  self->type->update(HMAC_STATE(self), length, data);
}

static struct lsh_string *
do_hmac_digest(struct mac_instance *s,
	       struct lsh_string *res, uint32_t start)
{
  CAST(hmac_instance, self, s);
  lsh_string_write_hmac(res, start, self->type, self->super.mac_size,
			HMAC_OUTER(self), HMAC_INNER(self), HMAC_STATE(self));
  return res;
}


/* GABA:
   (class
     (name hmac_algorithm)
     (super mac_algorithm)
     (vars
       (type . "const struct nettle_hash *")))
*/

static struct mac_instance *
make_hmac_instance(struct mac_algorithm *s,
                   uint32_t key_length,
                   const uint8_t *key)
{
  CAST(hmac_algorithm, self, s);
  NEW_VAR_OBJECT(hmac_instance, instance,
		 HMAC_SIZE(self->type));

  instance->type = self->type;
  
  hmac_set_key(HMAC_OUTER(instance), HMAC_INNER(instance),
	       HMAC_STATE(instance),
	       self->type, key_length, key);

  instance->super.mac_size = self->super.mac_size;
  instance->super.update = do_hmac_update;
  instance->super.digest = do_hmac_digest;

  return &instance->super;
}

struct mac_algorithm *
make_hmac_algorithm(const struct nettle_hash *h)
{
  NEW(hmac_algorithm, self);

  self->super.mac_size = h->digest_size;

  /* Recommended in RFC-2104 */
  self->super.key_size = h->digest_size;
  self->super.make_mac = make_hmac_instance;

  self->type = h;

  return &self->super;
}


/* Utility functions */

struct lsh_string *
hash_string_l(const struct nettle_hash *a,
	      uint32_t length, const uint8_t *data)
{
  struct hash_instance *hash = make_hash(a);
  struct lsh_string *out;

  hash_update(hash, length, data);
  out = hash_digest_string(hash);

  KILL(hash);

  return out;
}

struct lsh_string *
hash_string(const struct nettle_hash *a,
	    const struct lsh_string *in,
	    int free)
{
  struct lsh_string *out = hash_string_l(a, STRING_LD(in));

  if (free)
    lsh_string_free(in);

  return out;
}

struct lsh_string *
mac_string(struct mac_algorithm *a,
	   const struct lsh_string *key,
	   int kfree,
	   const struct lsh_string *in,
	   int ifree)
{
  struct lsh_string *out;
  struct mac_instance *mac
    = MAKE_MAC(a, lsh_string_length(key), lsh_string_data(key));

  MAC_UPDATE(mac, lsh_string_length(in), lsh_string_data(in));
  out = MAC_DIGEST_STRING(mac);

  KILL(mac);
  
  if (kfree)
    lsh_string_free(key);
  if (ifree)
    lsh_string_free(in);

  return out;
}

/* Consumes input string. */
struct lsh_string *
crypt_string(struct crypto_instance *c,
	     const struct lsh_string *in)
{
  struct lsh_string *out;
  uint32_t length = lsh_string_length(in);
  
  if (c->block_size && (length % c->block_size))
    return NULL;

  /* Do the encryption in place. The type cast is permissible
   * because we're conceptually freeing the string and reusing the
   * storage. */
  out = (struct lsh_string *) in;
  
  CRYPT(c, length, out, 0, in, 0);
  
  return out;
}

/* This is only used for encrypted private keys. */
/* Consumes input string. */
struct lsh_string *
crypt_string_pad(struct crypto_instance *c,
		 const struct lsh_string *in)
{
  struct lsh_string *s;
  uint32_t length = lsh_string_length(in);
  uint32_t pos;
  uint32_t pad = c->block_size - (length % c->block_size);
  
  assert(pad);
  
  s = ssh_format("%lfS%lr", in, pad, &pos);
  /* Use RFC 1423 and "generalized RFC 1423" as described in
   * PKCS#5 version 2. */
  lsh_string_set(s, pos, pad, pad);

  return crypt_string(c, s);
}

/* Consumes input string. */
struct lsh_string *
crypt_string_unpad(struct crypto_instance *c,
		   const struct lsh_string *in)
{
  struct lsh_string *out;
  uint32_t pad;
  uint32_t length = lsh_string_length(in);
  assert(length);
  
  out = crypt_string(c, in);
  if (!out)
    return NULL;

  length = lsh_string_length(out);
  pad = lsh_string_data(out)[length - 1];

  if ( (pad > 0) && (pad <= c->block_size) )
    {
      /* This should not happen, as crypt string
       * must return a multiple of the block size. */
      assert(pad <= length);

      lsh_string_trunc(out, length - pad);
      return out;
    }
  else
    {
      lsh_string_free(out);
      return NULL;
    }
}

struct keypair *
make_keypair(uint32_t type,
	     struct lsh_string *public,
	     struct signer *private)
{
  NEW(keypair, self);
  
  self->type = type;
  self->public = public;
  self->private = private;
  return self;
}
