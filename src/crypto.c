/* crypto.c
 *
 * Encryption classes on top of nettle.
 *
 * $Id$ */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "crypto.h"

#include "werror.h"
#include "xalloc.h"

#include "nettle/arcfour.h"
#include "nettle/aes.h"
#include "nettle/blowfish.h"
#include "nettle/cast128.h"
#include "nettle/des.h"
#include "nettle/serpent.h"
#include "nettle/twofish.h"

#include "nettle/cbc.h"

#include "nettle/hmac.h"

#include <assert.h>
#include <string.h>

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
		 UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(arcfour_instance, self, s);

  assert(!(length % 8));

  arcfour_crypt(&self->ctx, length, dst, src);
}

static struct crypto_instance *
make_arcfour_instance(struct crypto_algorithm *ignored UNUSED,
		      int mode UNUSED,
		      const UINT8 *key, const UINT8 *iv UNUSED)
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

/* AES/Rijndael */
/* GABA:
   (class
     (name aes_instance)
     (super crypto_instance)
     (vars
       (ctx . "struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE)")))
*/

static void
do_aes_encrypt(struct crypto_instance *s,
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(aes_instance, self, s);

  CBC_ENCRYPT(&self->ctx, aes_encrypt, length, dst, src);
}

static void
do_aes_decrypt(struct crypto_instance *s,
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(aes_instance, self, s);

  CBC_DECRYPT(&self->ctx, aes_decrypt, length, dst, src);
}

static struct crypto_instance *
make_aes_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                      const UINT8 *key, const UINT8 *iv)
{
  NEW(aes_instance, self);

  self->super.block_size = AES_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_aes_encrypt
			: do_aes_decrypt);

  aes_set_key(&self->ctx.ctx, algorithm->key_size, key);
  CBC_SET_IV(&self->ctx, iv);
  
  return(&self->super);
}

struct crypto_algorithm crypto_aes256_cbc_algorithm =
{ STATIC_HEADER, AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE, make_aes_cbc_instance};


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
		UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(des3_instance, self, s);

  CBC_ENCRYPT(&self->ctx, des3_encrypt, length, dst, src);
}

static void
do_des3_decrypt(struct crypto_instance *s,
		UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(des3_instance, self, s);

  CBC_DECRYPT(&self->ctx, des3_decrypt, length, dst, src);
}

static struct crypto_instance *
make_des3_cbc_instance(struct crypto_algorithm *algorithm UNUSED,
                       int mode,
                       const UINT8 *key, const UINT8 *iv)
{
  NEW(des3_instance, self);
  UINT8 pkey[DES3_KEY_SIZE];

  /* Fix odd parity */
  des_fix_parity(DES3_KEY_SIZE, pkey, key);
  
  self->super.block_size = DES3_BLOCK_SIZE;
  self->super.crypt = ( (mode == CRYPTO_ENCRYPT)
			? do_des3_encrypt
			: do_des3_decrypt);

  CBC_SET_IV(&self->ctx, iv);
  
  if (des3_set_key(&self->ctx.ctx, pkey))
    return(&self->super);

  switch(self->ctx.ctx.status)
    {
    case DES_BAD_PARITY:
      fatal("Internal error! Bad parity in make_des3_instance.\n");
    case DES_WEAK_KEY:
      werror("Detected weak DES key.\n");
      KILL(self);
      return NULL;
    default:
      fatal("Internal error!\n");
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
                   UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(cast128_instance, self, s);

  CBC_ENCRYPT(&self->ctx, cast128_encrypt, length, dst, src);
}

static void
do_cast128_decrypt(struct crypto_instance *s,
                   UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(cast128_instance, self, s);

  CBC_DECRYPT(&self->ctx, cast128_decrypt, length, dst, src);
}

static struct crypto_instance *
make_cast128_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                          const UINT8 *key, const UINT8 *iv UNUSED)
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
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(twofish_instance, self, s);

  CBC_ENCRYPT(&self->ctx, twofish_encrypt, length, dst, src);
}

static void
do_twofish_decrypt(struct crypto_instance *s,
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(twofish_instance, self, s);

  CBC_DECRYPT(&self->ctx, twofish_decrypt, length, dst, src);
}

static struct crypto_instance *
make_twofish_cbc_instance(struct crypto_algorithm *algorithm, int mode,
		      const UINT8 *key, const UINT8 *iv UNUSED)
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
                    UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(blowfish_instance, self, s);

  CBC_ENCRYPT(&self->ctx, blowfish_encrypt, length, dst, src);
}

static void
do_blowfish_decrypt(struct crypto_instance *s,
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(blowfish_instance, self, s);

  CBC_DECRYPT(&self->ctx, blowfish_decrypt, length, dst, src);
}

static struct crypto_instance *
make_blowfish_cbc_instance(struct crypto_algorithm *algorithm, int mode,
                           const UINT8 *key, const UINT8 *iv UNUSED)
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
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(serpent_instance, self, s);

  CBC_ENCRYPT(&self->ctx, serpent_encrypt, length, dst, src);
}

static void
do_serpent_decrypt(struct crypto_instance *s,
	       UINT32 length, const UINT8 *src, UINT8 *dst)
{
  CAST(serpent_instance, self, s);

  CBC_DECRYPT(&self->ctx, serpent_decrypt, length, dst, src);
}

static struct crypto_instance *
make_serpent_cbc_instance(struct crypto_algorithm *algorithm, int mode,
		      const UINT8 *key, const UINT8 *iv UNUSED)
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


/* HMAC */
/* GABA:
   (class
     (name hmac_sha1_instance)
     (super mac_instance)
     (vars
       (ctx . "struct hmac_sha1_ctx")))
*/

static void
do_hmac_sha1_update(struct mac_instance *s,
		    UINT32 length, const UINT8 *data)
{
  CAST(hmac_sha1_instance, self, s);

  hmac_sha1_update(&self->ctx, length, data);
}

static void
do_hmac_sha1_digest(struct mac_instance *s,
		    UINT8 *data)
{
  CAST(hmac_sha1_instance, self, s);

  hmac_sha1_digest(&self->ctx, SHA1_DIGEST_SIZE, data);
}

#if 0
/* Not actually used anywhere */
static struct mac_instance *
do_hmac_sha1_copy(struct mac_instance *s)
{
  CAST(hmac_sha1_instance, self, s);
  CLONED(hmac_sha1_instance, new, self);

  return &new->super;
}
#endif

static struct mac_instance *
make_hmac_sha1_instance(struct mac_algorithm *self,
			UINT32 key_length,
			const UINT8 *key)
{
  NEW(hmac_sha1_instance, hash);

  hmac_sha1_set_key(&hash->ctx, key_length, key);

  hash->super.hash_size = self->hash_size;
  hash->super.update = do_hmac_sha1_update;
  hash->super.digest = do_hmac_sha1_digest;
  hash->super.copy = NULL;

  return &hash->super;
}

/* RFC-2104 recommends using key_size = hash_size */
struct mac_algorithm
crypto_hmac_sha1_algorithm =
  { STATIC_HEADER, SHA1_DIGEST_SIZE, SHA1_DIGEST_SIZE,
    make_hmac_sha1_instance };

/* GABA:
   (class
     (name hmac_md5_instance)
     (super mac_instance)
     (vars
       (ctx . "struct hmac_md5_ctx")))
*/

static void
do_hmac_md5_update(struct mac_instance *s,
		    UINT32 length, const UINT8 *data)
{
  CAST(hmac_md5_instance, self, s);

  hmac_md5_update(&self->ctx, length, data);
}

static void
do_hmac_md5_digest(struct mac_instance *s,
		    UINT8 *data)
{
  CAST(hmac_md5_instance, self, s);

  hmac_md5_digest(&self->ctx, MD5_DIGEST_SIZE, data);
}

static struct mac_instance *
make_hmac_md5_instance(struct mac_algorithm *self,
		       UINT32 key_length,
		       const UINT8 *key)
{
  NEW(hmac_md5_instance, hash);

  hmac_md5_set_key(&hash->ctx, key_length, key);

  hash->super.hash_size = self->hash_size;
  hash->super.update = do_hmac_md5_update;
  hash->super.digest = do_hmac_md5_digest;
  hash->super.copy = NULL;

  return &hash->super;
}

struct mac_algorithm
crypto_hmac_md5_algorithm =
  { STATIC_HEADER, MD5_DIGEST_SIZE, MD5_DIGEST_SIZE,
    make_hmac_md5_instance };

/* FIXME: This is a ugly.
 *
 * The right way to do things is probably to add a pointer to a struct
 * nettle_hash in our hash_algorithm class, and make hash_instance and
 * mac_instance variable size objects where the context comes last. */
struct mac_algorithm *
make_hmac_algorithm(struct hash_algorithm *h)
{
  if (h == &sha1_algorithm)
    return &crypto_hmac_sha1_algorithm;
  else if (h == &md5_algorithm)
    return &crypto_hmac_md5_algorithm;

  fatal("make_hmac_algorithm: Unknown hash algorithm\n");
}
