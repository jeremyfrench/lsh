/* read_packet.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "read_packet.h"

#include "crypto.h"
#include "format.h"
#include "io.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define WAIT_START 0
#define WAIT_HEADER 1
#define WAIT_CONTENTS 2
#define WAIT_MAC 3

#include "read_packet.c.x"


/* GABA:
   (class
     (name read_packet)
     (super read_handler)
     (vars
       (state . int)
  
       ; Attached to read packets
       (sequence_number . uint32_t)
  
       ; Buffer index, used for all the buffers
       (pos . uint32_t)

       ; NOTE: This buffer should hold one block, and must be
       ; reallocated when the crypto algorithms is changed. 
       (block_buffer string)

       ; Must point to an area large enough to hold a mac 
       (mac_buffer string) 

       ; Holds the packet payload
       (packet_buffer string)

       ; Position in the buffer after the first,
       ; already decrypted, block.
       (crypt_pos . "uint8_t *")
  
       (handler object abstract_write)
       (connection object ssh_connection)))
*/

static struct lsh_string *
lsh_string_realloc(struct lsh_string *s, uint32_t length)
{
  if (!s)
    return lsh_string_alloc(length);

  if (s->length < length)
    {
      lsh_string_free(s);
      return lsh_string_alloc(length);
    }
  else
    return s;
}


#define READ(n, dst) do {				\
  memcpy((dst)->data + closure->pos, data, (n));	\
  closure->pos += (n);					\
  data += (n);						\
  total += (n);						\
  available -= (n);					\
} while (0)

static uint32_t
do_read_packet(struct read_handler **h,
	       uint32_t available,
	       uint8_t *data /*, struct exception_handler *e */)
{
  CAST(read_packet, closure, *h);
  uint32_t total = 0;

  if (!available)
    {
      debug("read_packet: EOF in state %i\n", closure->state);

      if (closure->state != WAIT_START)
        EXCEPTION_RAISE(closure->connection->e,
                        make_protocol_exception(0, "Unexpected EOF"));
      else
        /* FIXME: This may still be "unexpected".
         *
         * We should check that there's no open channels. */
        EXCEPTION_RAISE(closure->connection->e, &finish_read_exception);
      
      *h = NULL;
      return 0;
    }
	  
  for (;;)
    switch(closure->state)
      {
      case WAIT_START:
	{
	  uint32_t block_size = closure->connection->rec_crypto
	    ? closure->connection->rec_crypto->block_size : 8;

	  closure->block_buffer
	    = lsh_string_realloc(closure->block_buffer,
				 block_size);

	  if (closure->connection->rec_mac)
	    closure->mac_buffer = lsh_string_realloc
	      (closure->mac_buffer,
	       closure->connection->rec_mac->mac_size);

	  /* FALL THROUGH */
	}
	/* do_header: */
        closure->state = WAIT_HEADER;
	closure->pos = 0;
	/* FALL THROUGH */
	  
      case WAIT_HEADER:
	{
	  uint32_t block_size = closure->connection->rec_crypto
	    ? closure->connection->rec_crypto->block_size : 8;
	  uint32_t left;

	  left = block_size - closure->pos;
	  assert(left);

	  if (available < left)
	    {
	      READ(available, closure->block_buffer);

	      return total;
	    }
	  else
	    {
	      /* We have read a complete block */
	      uint32_t length;

	      READ(left, closure->block_buffer);
	    
	      if (closure->connection->rec_crypto)
		CRYPT(closure->connection->rec_crypto,
		      block_size,
		      closure->block_buffer->data,
		      closure->block_buffer->data);
		
	      length = READ_UINT32(closure->block_buffer->data);

	      /* NOTE: We don't implement a limit at _exactly_
	       * rec_max_packet, as we don't include the length field
	       * and MAC in the comparison below. */
	      if (length > (closure->connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
		{
		  static const struct protocol_exception too_large =
		    STATIC_PROTOCOL_EXCEPTION(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Packet too large");
		  
		  werror("read_packet: Receiving too large packet.\n"
			 "  %i octets, limit is %i\n",
			 length, closure->connection->rec_max_packet);
		  
		  EXCEPTION_RAISE(closure->connection->e, &too_large.super);

		  return total;
		}

	      if ( (length < 12)
		   || (length < (block_size - 4))
		   || ( (length + 4) % block_size))
		{
		  static const struct protocol_exception invalid =
		    STATIC_PROTOCOL_EXCEPTION(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Invalid packet length");
		  
		  werror("read_packet: Bad packet length %i\n",
			 length);
		  EXCEPTION_RAISE(closure->connection->e, &invalid.super);

		  return total;
		}

	      /* Process this block before the length field is lost. */
	      if (closure->connection->rec_mac)
		{
		  uint8_t s[4];
		  WRITE_UINT32(s, closure->sequence_number);
		    
		  MAC_UPDATE(closure->connection->rec_mac, 4, s);
		  MAC_UPDATE(closure->connection->rec_mac,
			      block_size,
			      closure->block_buffer->data);
		}

	      /* Allocate full packet */
	      {
		unsigned done = block_size - 4;

		assert(!closure->packet_buffer);
		
		closure->packet_buffer
		  = ssh_format("%ls%lr",
			       done,
			       closure->block_buffer->data + 4,
			       length - done,
			       &closure->crypt_pos);

		/* The sequence number is needed by the handler for
		 * unimplemented message types. */
		closure->packet_buffer->sequence_number
		  = closure->sequence_number++;

		closure->pos = done;

		if (done == length)
		  {
		    /* A complete ssh packet fitted in the first
		     * encryption block. */
		    debug("read_packet.c: "
			  "Going directly to the WAIT_MAC state\n");

		    goto do_mac;
		  }
		else
		  goto do_contents;
	      }
	    }
	}
	fatal("read_packet: Supposedly not happening???\n");
	  
      do_contents:
        closure->state = WAIT_CONTENTS;
	
      case WAIT_CONTENTS:
	{
	  uint32_t left = closure->packet_buffer->length - closure->pos;

	  assert(left);

	  if (available < left)
	    {
	      READ(available, closure->packet_buffer);
	    
	      return total;
	    }
	  else
	    {
	      /* Read a complete packet */
	      READ(left, closure->packet_buffer);

	      left = ( (closure->packet_buffer->length + closure->packet_buffer->data)
		       - closure->crypt_pos );

	      if (closure->connection->rec_crypto)
		CRYPT(closure->connection->rec_crypto,
		      left,
		      closure->crypt_pos,
		      closure->crypt_pos);		      

	      if (closure->connection->rec_mac)
		MAC_UPDATE(closure->connection->rec_mac,
			   left,
			   closure->crypt_pos);

	      goto do_mac;
	    }
	}
	fatal("read_packet: Supposedly not happening???\n");

      do_mac:
        closure->state = WAIT_MAC;
	closure->pos = 0;
      
      case WAIT_MAC:

	if (closure->connection->rec_mac)
	  {
	    uint32_t left = (closure->connection->rec_mac->mac_size
			   - closure->pos);

	    assert(left);

	    if (available < left)
	      {
		READ(available, closure->mac_buffer);
	      
		return total;
	      }
	    else
	      {
		/* Read a complete MAC */

		uint8_t *mac;

		READ(left, closure->mac_buffer);

		mac = alloca(closure->connection->rec_mac->mac_size);
		MAC_DIGEST(closure->connection->rec_mac, mac);
	    
		if (memcmp(mac,
			   closure->mac_buffer->data,
			   closure->connection->rec_mac->mac_size))
		  {
		    static const struct protocol_exception mac_error =
		      STATIC_PROTOCOL_EXCEPTION(SSH_DISCONNECT_MAC_ERROR,
						"MAC error");

		    EXCEPTION_RAISE(closure->connection->e, &mac_error.super);
		    return total;
		  }
	      }
	  }
	
	/* MAC was ok, send packet on */
	{
	  struct lsh_string *packet = closure->packet_buffer;
	  
	  closure->packet_buffer = NULL;
	  closure->state = WAIT_START;

	  A_WRITE(closure->handler, packet);

	  return total;
	}
      default:
	fatal("Internal error\n");
    }
}

struct read_handler *
make_read_packet(struct abstract_write *handler,
		 struct ssh_connection *connection)
{
  NEW(read_packet, closure);

  closure->super.handler = do_read_packet;

  closure->connection = connection;
  closure->handler = handler;

  closure->state = WAIT_START;
  closure->sequence_number = 0;

  closure->block_buffer = NULL;
  closure->mac_buffer = NULL;
  closure->packet_buffer = NULL;
  
  return &closure->super;
}
