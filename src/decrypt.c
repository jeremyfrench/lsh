/* decrypt.c
 *
 */

#include "decrypt.c"

#define WAIT_HEADER 0
#define WAIT_CONTENTS 1
#define WAIT_MAC 2

static int do_decrypt(struct encrypt_processor *closure,
		      struct simple_packet *packet)
{
  /* Number of octets n the input packet that have been processed */
  UINT32 pos = 0;

  while(pos < packet->length)
    switch(closure->state)
      {
      case WAIT_HEADER:
	{
	  UINT32 left = closure->block_size - closure->pos;
	  UINT32 copy = MIN(left, (packet->length - pos));

	  memcpy(closure->block_buffer + closure->pos,
		 packet->data + pos,
		 copy);

	  pos += copy;
	  closure->pos += copy;
	  
	  if (left == copy)
	    {
	      /* Read a full header */
	      UINT32 length;

	      /* Decrypt the first block */
	      closure->decrypt_function(closure->decrypt_state,
					block_size, closure->block_buffer,
					closure->block_buffer);

	      length = READ_INT32(closure->block_buffer);

	      if (length > closure->max_packet)
		return 0;

	      if ( (length < 12)
		   || (length < (closure->block_size - 4))
		   || ( (length + 4) % closure->block_size))
		return 0;
	      
	      /* The length of remaining data. Note that the first,
	       * already decrypted, block contains some of the
	       * decypted payload. */
	      closure->recieved
		= simple_packet_alloc(length
				      - (closure->block_size - 4));
	      
	      closure->pos = 0;
	      closure->state = WAIT_CONTENTS;
	      /* Fall through to WAIT_CONTNTS */
	    }
	  else
	    /* Processed all octets of this packet. Still no complete
	     * header. */
	    break;
	}
      case WAIT_CONTENTS:
	{
	  UINT32 left = closure->recieved->length - closure->pos;
	  UINT32 copy = MIN(left, packet->length - pos);

	  memcpy(closure->recieved->data + closure->pos,
		 packet->data + pos,
		 copy);

	  pos += copy;
	  closure->pos += copy;

	  if (left == copy)
	    {
	      /* Read a complete packet (but no MAC yet) */

	      UINT32 left_overs = closure->block_size - 4;
	      /* Full packet (including left-overs from the first block) */
	      struct simple_packet *new
		= simple_packet_alloc(closure->recieved->length
				      + left_overs);

	      memcpy(new->data, closure->block_buffer + 4,
		     left_overs);

	      closure->decrypt_function(closure->decrypt_state,
					closure->recieved->length,
					new->data + left_overs);

	      simple_packet_free(closure->recieved);
	      closure->recieved = new;

	      if (closure->mac_size)
		closure->mac_function(closure->mac_state,
				      new->length,
				      new->data,
				      closure->block_buffer);

	      closure->pos = 0;
	      closure->state = WAIT_MAC;

	      /* Fall through */
	    }
	  else
	    /* Processe all octets, but still haven't got a complete packet */
	    break;
	}
      case WAIT_MAC:
	if (closure->mac_size)
	  {
	    UINT32 left = closure->mac_size - closure->pos;
	    UINT32 cmp = MIN(left, packet->length - pos);

	    if (!memcpy(closure->block_buffer + closure->pos,
			packet->data + pos,
			cmp))
	      return 0;

	    pos += cmp;
	    closure->pos += cmp;

	    if (left > cmp)
	      {
		/* Processed all octets, but still haven't received a
                   complete MAC */
		break;
	      }
	  }
	/* MAC was ok, pass packet on */
	
	if (!apply_continuation(closure->next, closure->recieved))
	  return 0;
	
	closure->recieved = NULL;
	closure->pos = 0;
	closure->state = WAIT_HEADER;
	break;

      default:
	fatal("Internal error");
      }
  /* Processed all octets of this packet. */
  return 1;
}
  
struct packet_processor *
make_encrypt_processor(struct packet_processor *continuation,
		       UINT32 max_packet,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       unsigned block_size,
		       transform_function encrypt_function,
		       void *encrypt_state)
{
  struct pad_processor *closure = xalloc(sizeof(struct pad_processor)
					 + MAX(block_size, mac_size) - 1);
  
  closure->c->p->f = (raw_processor_function) do_encrypt;
  closure->c->next = continuation;

  /* state */
  closure->state = WAIT_HEADER;
  closure->pos = 0;
  closure->recieved = NULL;
  
  closure->max_packet = max_packet;
  
  closure->mac_size = mac_size;
  closure->mac_function = mac_function;
  closure->mac_state = mac_state;
  closure->block_size = block_size;
  closure->encrypt_function = encrypt_function;
  closure->encrypt_state = encrypt_state;

  return (struct packet_processor *) closure;
}
