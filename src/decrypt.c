/* decrypt.c
 *
 */

#include "decrypt.h"
#include "werror.h"
#include "xalloc.h"

#define WAIT_HEADER 0
#define WAIT_CONTENTS 1
#define WAIT_MAC 2

#define MIN(a, b) ( ((a)<(b)) ? (a) : (b) )
#define MAX(a, b) ( ((a)>(b)) ? (a) : (b) )

static int do_decrypt(struct decrypt_processor *closure,
		      struct lsh_string *packet)
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
					closure->block_size, closure->block_buffer,
					closure->block_buffer);

	      length = READ_UINT32(closure->block_buffer);

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
		= lsh_string_alloc(length
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
	      struct lsh_string *new
		= lsh_string_alloc(closure->recieved->length
				      + left_overs);

	      memcpy(new->data, closure->block_buffer + 4,
		     left_overs);

	      closure->decrypt_function(closure->decrypt_state,
					closure->recieved->length,
					closure->recieved->data,
					new->data + left_overs);

	      lsh_string_free(closure->recieved);
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
	
	if (!apply_processor(closure->c.next, closure->recieved))
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
  
struct abstract_write *
make_decrypt_processor(struct abstract_write *continuation,
		       UINT32 max_packet,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       unsigned block_size,
		       transform_function decrypt_function,
		       void *decrypt_state)
{
  struct decrypt_processor *closure = xalloc(sizeof(struct decrypt_processor)
					 + MAX(block_size, mac_size) - 1);
  
  closure->c.p.f = (abstract_write_f) do_decrypt;
  closure->c.next = continuation;

  /* state */
  closure->state = WAIT_HEADER;
  closure->pos = 0;
  closure->recieved = NULL;
  
  closure->max_packet = max_packet;
  
  closure->mac_size = mac_size;
  closure->mac_function = mac_function;
  closure->mac_state = mac_state;
  closure->block_size = block_size;
  closure->decrypt_function = decrypt_function;
  closure->decrypt_state = decrypt_state;

  return (struct abstract_write *) closure;
}
