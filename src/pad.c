/* pad.c
 *
 */

#include "pad.h"
#include "xalloc.h"
#include <assert.h>

static int do_pad(struct abstract_write **w,
		  struct lsh_string *packet)
{
  struct packet_pad *closure
    = (struct packet_pad *) *w;
  
  UINT32 new_size;
  UINT8 padding;

  struct lsh_string *new;

  new_size = 1 + closure->block_size
    * ( (8 + packet->length) / closure->block_size);

  padding = new_size - packet->length - 5;
  assert(padding >= 4);

  /* FIXME: Use ssh_format() */
  new = lsh_string_alloc(new_size);

  WRITE_UINT32(new->data, new_size - 4);
  new->data[4] = padding;
  
  memcpy(new->data + 5, packet->data, packet->length);
  RANDOM(closure->random, padding, new->data + 5 + packet->length);
  
  lsh_string_free(packet);

  return A_WRITE(closure->super.next, new);
}
  
struct abstract_write *
make_packet_pad(struct abstract_write *continuation,
		unsigned block_size,
		struct randomness *random)
{
  struct packet_pad *closure = xalloc(sizeof(struct packet_pad));

  closure->super.super.write = do_pad;
  closure->super.next = continuation;
  closure->block_size = block_size;
  closure->random = random;

  return &closure->super.super;
}
