/* pad.c
 *
 */

#include "pad.h"

static int do_pad(struct pad_processor *closure,
		  struct simple_packet *packet)
{
  UINT32 new_size;
  UINT8 padding;

  struct simple_packet *new;
  struct ssh_packet *ssh;

  new_size = 1 + closure->block_size
    * ( (8 + packet->length) / closure->block_size);

  padding = new_size - packet->length - 5;
  assert(ssh->padding_length >= 4);
  
  new = simple_packet_alloc(new_size);
  ssh = (struct ssh_packet *) new->data;

  ssh->length = htonl(new_size);
  ssh->padding_length = padding;

  memcpy(ssh->data, packet->data, packet->length);
  closure->random(closure->state, padding, ssh->data + packet->length);

  simple_packet_free(packet);

  return apply_processor(closure->c->next, new);
}
  

struct packet_processor *make_pad_processor(packet_processor *continuation,
					    unsigned block_size,
					    random_function random,
					    void *state)
{
  struct pad_processor *closure = xalloc(sizeof(struct pad_processor));

  closure->c->p->f = (raw_processor_function) do_pad;
  closure->c->next = continuation;
  closure->block_size = block_size;
  closure->random = random;
  closure->state = state;

  return (struct packet_processor *) closure;
}
