/* pad.c
 *
 */

#include "pad.h"
#include "xalloc.h"
#include <assert.h>

static int do_pad(struct pad_processor *closure,
		  struct lsh_string *packet)
{
  UINT32 new_size;
  UINT8 padding;

  struct lsh_string *new;

#if 0
  struct ssh_packet *ssh;
#endif
  
  new_size = 1 + closure->block_size
    * ( (8 + packet->length) / closure->block_size);

  padding = new_size - packet->length - 5;
  assert(padding >= 4);

  /* FIXME: Use ssh_format() */
  new = lsh_string_alloc(new_size);

#if 0
  ssh = (struct ssh_packet *) new->data; 
  ssh->length = htonl(new_size);
  ssh->padding_length = padding;
#endif

  WRITE_UINT32(new->data, new_size - 4);
  new->data[4] = padding;
  
  memcpy(new->data + 5, packet->data, packet->length);
  closure->random(closure->state, padding, new->data + 5 + packet->length);

  lsh_string_free(packet);

  return apply_processor(closure->c.next, new);
}
  

struct abstract_write *
make_pad_processor(struct abstract_write *continuation,
		   unsigned block_size,
		   random_function random,
		   void *state)
{
  struct pad_processor *closure = xalloc(sizeof(struct pad_processor));

  closure->c.p.f = (abstract_write_f) do_pad;
  closure->c.next = continuation;
  closure->block_size = block_size;
  closure->random = random;
  closure->state = state;

  return (struct abstract_write *) closure;
}
