/* randomness.c
 *
 */

#include "randomness.h"
#include "abstract_crypto.h"

/* Random */
struct poor_random
{
  struct randomness super;
  struct hash_instance *hash;
  UINT32 pos;
  UINT8 buffer[1];
};

static void do_poor_random(struct randomness **r, UINT32 length, UINT8 *dst)
{
  struct poor_random *self = (struct poor_random *) *r;

  while(length)
    {
      UINT32 available = self->hash->hash_size - self->pos;
      UINT32 to_copy;
      
      if (!available)
	{
	  time_t now = time(NULL); /* To avoid cycles */
	  HASH_UPDATE(self->hash, sizeof(now), (UINT8 *) &now);
	  HASH_UPDATE(self->hash, self->hash->hash_size,
		      self->buffer);
	  HASH_DIGEST(self->hash, self->buffer);

	  available = self->hash->hash_size;
	  self->pos = 0;
	}
      to_copy = MIN(available, length);

      memcpy(dst, self->buffer + self->pos, to_copy);
      length -= to_copy;
      dst += to_copy;
      self->pos += to_copy;
    }
}

struct randomness *make_poor_random(struct hash_algorithm *hash,
				    struct lsh_string *init)
{
  struct poor_random *self
    = xalloc(sizeof(struct poor_random) - 1 + hash->hash_size);
  time_t now = time(NULL); /* To avoid cycles */
    
  self->super.random = do_poor_random;
  self->hash = MAKE_HASH(hash);

  HASH_UPDATE(self->hash, sizeof(now), (UINT8 *) &now);
  HASH_UPDATE(self->hash, init->length, init->data);
  HASH_DIGEST(self->hash, self->buffer);
  
  self->pos = 0;

  return &self->super;
}
