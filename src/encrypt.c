/* encrypt.c
 *
 */

#include "encrypt.h"
#include "xalloc.h"

static int do_encrypt(struct encrypt_processor *closure,
		      struct simple_packet *packet)
{
  struct simple_packet *new
    = simple_packet_alloc(packet->length + closure->mac_size);

  closure->encrypt_function(closure->encrypt_state,
			    packet->length,
			    packet->data, new->data);

  if (closure->mac_size)
    closure->mac_function(closure->mac_state,
			  packet->length,
			  packet->data, new->data + packet->length);
  
  simple_packet_free(packet);

  return apply_processor(closure->c.next, new);
}

struct packet_processor *
make_encrypt_processor(struct packet_processor *continuation,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       transform_function encrypt_function,
		       void *encrypt_state)
{
  struct encrypt_processor *closure = xalloc(sizeof(struct encrypt_processor));

  closure->c.p.f = (raw_processor_function) do_encrypt;
  closure->c.next = continuation;
  closure->mac_size = mac_size;
  closure->mac_function = mac_function;
  closure->mac_state = mac_state;
  closure->encrypt_function = encrypt_function;
  closure->encrypt_state = encrypt_state;

  return (struct packet_processor *) closure;
}

    
