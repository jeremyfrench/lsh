/* crypto.c
 *
 */

#include <sys/types.h>
#include <time.h>

#include "crypto.h"
#include "sha.h"
#include "rc4.h"
#include "werror.h"
#include "xalloc.h"

/* No crypto */
static void do_crypt_none(struct crypto_instance *ignored,
			  UINT32 length, UINT8 *dst, UINT8 *src)
{
  if (length % 8)
    fatal("Internal error\n");
  if (src != dst)
    memcpy(dst, src, length);
}

struct crypto_instance crypto_none_instance =
{
  8,
  do_crypt_none
};

struct rc4_instance
{
  struct crypto_instance super;
  struct rc4_ctx ctx;
};

static void do_crypt_rc4(struct crypto_instance *s,
			  UINT32 length, UINT8 *dst, UINT8 *src)
{
  struct rc4_instance *self = (struct rc4_instance *) s;

  if (length % 8)
    fatal("Internal error\n");

  rc4_crypt(&self->ctx, dst, src, length);
}

static struct crypto_instance *
make_rc4_instance(struct crypto_algorithm *ignored, int mode, UINT8 *key)
{
  struct rc4_instance *self = xalloc(sizeof(struct rc4_instance));

  self->super.block_size = 8;
  self->super.crypt = do_crypt_rc4;

  rc4_set_key(&self->ctx, key, 16);

  return &self->super;
}

struct crypto_algorithm crypto_rc4_algorithm =
{ 8, 16, make_rc4_instance };

/* SHA1 hash */
struct sha_instance
{
  struct hash_instance super;
  struct sha_ctx ctx;
};

static void do_sha_update(struct hash_instance *s,
			  UINT32 length, UINT8 *data)
{
  struct sha_instance *self = (struct sha_instance *) s;
  sha_update(&self->ctx, data, length);
}

static void do_sha_digest(struct hash_instance *s,
			  UINT8 *dst)
{
  struct sha_instance *self = (struct sha_instance *) s;
  sha_final(&self->ctx);
  sha_digest(&self->ctx, dst);
  sha_init(&self->ctx);
}

static struct hash_instance *do_sha_copy(struct hash_instance *s)
{
  struct sha_instance *self = (struct sha_instance *) s;
  struct sha_instance *new = xalloc(sizeof(struct sha_instance));
  memcpy(new, self, sizeof(*self));
  return &new->super;
}

static struct hash_instance *make_sha_instance(struct hash_algorithm *ignored)
{
  struct sha_instance *res = xalloc(sizeof(struct sha_instance));

  res->super.hash_size = 20;
  res->super.update = do_sha_update;
  res->super.digest = do_sha_digest;
  res->super.copy = do_sha_copy;

  sha_init(&res->ctx);

  return &res->super;
}

struct hash_algorithm sha_algorithm =
{ SHA_DATASIZE, SHA_DIGESTSIZE, make_sha_instance };

/* HMAC */

struct hmac_algorithm
{
  struct mac_algorithm super;
  struct hash_algorithm *hash;
};

struct hmac_instance
{
  struct mac_instance super;
  /* Initialized hash objects */
  struct hash_instance *hinner;
  struct hash_instance *houter;

  /* Modified by update */
  struct hash_instance *state;
};

static void do_hmac_update(struct mac_instance *s,
			   UINT32 length, UINT8 *data)
{
  struct hmac_instance *self = (struct hmac_instance *) s;
  HASH_UPDATE(self->state, length, data);
}

static void do_hmac_digest(struct mac_instance *s,
			   UINT8 *data)
{
  struct hmac_instance *self = (struct hmac_instance *) s;
  struct hash_instance *h = self->state;
  
  HASH_DIGEST(h, data);   /* Inner hash */
  lsh_free(h);
  h = HASH_COPY(self->houter);
  HASH_UPDATE(h, self->super.mac_size, data);
  HASH_DIGEST(h, data);
  lsh_free(h);

  self->state = HASH_COPY(self->hinner);
}

static struct mac_instance *do_hmac_copy(struct mac_instance *s)
{
  struct hmac_instance *self = (struct hmac_instance *) s;
  struct hmac_instance *new = xalloc(sizeof(struct hmac_instance));

  memcpy(&new->super, &self->super, sizeof(self->super));

  /* FIXME: Sharing hinner and houter objects makes gc more difficult */
  new->hinner = self->hinner;
  new->houter = self->houter;
  new->state = HASH_COPY(self->state);

  return &new->super;
}

#define IPAD 0x36
#define OPAD 0x5c

static struct mac_instance *make_hmac_instance(struct mac_algorithm *s,
					       UINT8 *key)
{
  struct hmac_algorithm *self = (struct hmac_algorithm *) s;
  struct hmac_instance *instance = xalloc(sizeof(struct hmac_instance));
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
  struct hmac_algorithm *self = xalloc(sizeof(struct hmac_algorithm));

  self->super.hash_size = h->hash_size;
  /* Recommended in RFC-2104 */
  self->super.key_size = h->hash_size;
  self->super.make_mac = make_hmac_instance;

  self->hash = h;

  return &self->super;
}

