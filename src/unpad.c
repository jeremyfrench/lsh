/* unpad.c
 *
 */

#include "unpad.h"
#include "xalloc.h"

static int do_unpad(struct unpad_processor *closure,
		    struct lsh_string *packet)
{
  UINT8 padding_length;
  UINT32 payload_length;
  struct lsh_string *new;
  
  if (packet->length < 1)
    return 0;
  
  padding_length = packet->data[0];

  if ( (padding_length < 4)
       || (padding_length >= packet->length) )
    return 0;

  payload_length = packet->length - 1 - padding_length;
  
  /* FIXME: Use ssh_format() */
  new = lsh_string_alloc(payload_length);

  memcpy(new->data, packet->data + 1, payload_length);

  lsh_string_free(packet);

  return apply_processor(closure->c.next, new);
}

struct abstract_write *
make_packet_unpad(struct abstract_write *continuation)
{
  struct unpad_processor *closure = xalloc(sizeof(struct unpad_processor));

  closure->c.p.f = (abstract_write_f) do_unpad;
  closure->c.next = continuation;

  return (struct abstract_write *) closure;
}
