/* unpad.c
 *
 */

static int do_unpad(struct pad_processor *closure,
		    struct simple_packet *packet)
{
  UINT8 padding_length;
  UINT32 payload_length;
  struct simple_packet *new;
  
  if (packet->length < 1)
    return 0;
  
  padding_length = packet->data[0];

  if ( (padding_length < 4)
       || (padding_length >= packet->length) )
    return 0;

  payload_length = packet->length - 1 - padding_length;
  
  new = simple_packet_alloc(payload_length);

  memcpy(new->data, packet->data + 1, payload_length);

  simple_packet_free(packet);

  return apply_continuation(closure->next, new);
}

struct packet_processor *make_pad_processor(packet_processor *continuation)
{
  struct pad_processor *closure = xalloc(sizeof(struct pad_processor));

  closure->c->p->f = (raw_processor_function) do_unpad;
  closure->c->next = continuation;

  return (struct packet_processor *) closure;
}
