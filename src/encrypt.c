/* encrypt.c
 *
 */

#include "encrypt.h"
#include "xalloc.h"

static int do_encrypt(struct encrypt_processor **c,
		      struct simple_packet *packet)
{
  struct encrypt_processor *closure
    = (struct encrypt_processor *) *c;
  
  /* FIXME: Use ssh_format() */
  struct simple_packet *new
    = lsh_string_alloc(packet->length + closure->mac_size);

  closure->encrypt_function(closure->encrypt_state,
			    packet->length,
			    packet->data, new->data);

  if (closure->mac_size)
    closure->mac_function(closure->mac_state,
			  packet->length,
			  packet->data, new->data + packet->length);
  
  lsh_string_free(packet);

  return apply_processor(closure->c.next, new);
}

struct abstract_write *
make_packet_encrypt(struct abstract_write *continuation,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       transform_function encrypt_function,
		       void *encrypt_state)
{
  struct encrypt_processor *closure = xalloc(sizeof(struct encrypt_processor));

  closure->super.super.write = do_encrypt;
  closure->c.next = continuation;
  closure->mac_size = mac_size;
  closure->mac_function = mac_function;
  closure->mac_state = mac_state;
  closure->encrypt_function = encrypt_function;
  closure->encrypt_state = encrypt_state;

  return &closure->super.super;
}

    
