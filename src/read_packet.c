/* read_packet.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "read_packet.h"

#include "crypto.h"
#include "format.h"
#include "io.h"
#include "werror.h"
#include "xalloc.h"

#define WAIT_START 0
#define WAIT_HEADER 1
#define WAIT_CONTENTS 2
#define WAIT_MAC 3

#include "read_packet.c.x"

/* CLASS:
   (class
     (name read_packet)
     (super read_handler)
     (vars
       (state simple int)
  
       ; Attached to read packets
       (sequence_number simple UINT32)
  
       ; Buffer partial headers and packets.
       (pos simple UINT32)

       ; NOTE: This buffer should hold one block, and must be
       ; reallocated when the crypto algorithms is changed. 
       (buffer string)
       (crypt_pos simple "UINT8 *")

       ; Must point to an area large enough to hold a mac 
       (recieved_mac string) 
  
       (handler object abstract_write)
       (connection object ssh_connection)))
*/
     
#if 0
struct read_packet
{
  struct read_handler super; /* Super type */

  int state;
  
  UINT32 sequence_number; /* Attached to read packets */
  
  /* Buffer partial headers and packets. */
  UINT32 pos;

  /* FIXME: This buffer should hold one block, and must be reallocated
   * when the crypto algorithms is changed. */
  struct lsh_string *buffer;
  UINT8 *crypt_pos;

  /* Must point to an area large enough to hold a mac */
  struct lsh_string *recieved_mac; 
  
  struct abstract_write *handler;
  struct ssh_connection *connection;
};
#endif

static struct lsh_string *
lsh_string_realloc(struct lsh_string *s, UINT32 length)
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

/* For efficiency, allow reading several packets at a time. Butin
 * order not to starve other channels, return when this much data has
 * been read. */
#define QUANTUM 1024

static int do_read_packet(struct read_handler **h,
			  struct abstract_read *read)
{
  CAST(read_packet, closure, *h);
  int total = 0;
  
  while (total < QUANTUM)
    switch(closure->state)
      {
      case WAIT_START:
	{
	  UINT32 block_size = closure->connection->rec_crypto
	    ? closure->connection->rec_crypto->block_size : 8;

	  closure->buffer = lsh_string_realloc(closure->buffer,
					       block_size);
	  if (closure->connection->rec_mac)
	    closure->recieved_mac = lsh_string_realloc
	      (closure->recieved_mac,
	       closure->connection->rec_mac->hash_size);

	  closure->pos = 0;

	  closure->state = WAIT_HEADER;
	  /* FALL THROUGH */
	}
      case WAIT_HEADER:
	{
	  UINT32 block_size = closure->connection->rec_crypto
	    ? closure->connection->rec_crypto->block_size : 8;
	  UINT32 left;
	  int n;

	  left = block_size - closure->pos;
	    
	  n = A_READ(read, left, closure->buffer->data + closure->pos);
	  switch(n)
	    {
	    case 0:
	      return LSH_OK | LSH_GOON;
	    case A_FAIL:
	      return LSH_FAIL | LSH_DIE;
	    case A_EOF:
	      /* FIXME: Free associated resources! */
	      return LSH_OK | LSH_CLOSE;
	    }
	  closure->pos += n;
	  total += n;
	  
	  /* Read a complete block? */
	  if (n == left)
	    {
	      UINT32 length;

	      if (closure->connection->rec_crypto)
		CRYPT(closure->connection->rec_crypto,
		      block_size,
		      closure->buffer->data,
		      closure->buffer->data);
		
	      length = READ_UINT32(closure->buffer->data);
	      if (length > closure->connection->rec_max_packet)
		{
		  werror("read_packet: Recieving too large packet.\n"
			 "  %d octets, limit is %d\n",
			 length, closure->connection->rec_max_packet);
		  return LSH_FAIL | LSH_DIE;
		}

	      if ( (length < 12)
		   || (length < (block_size - 4))
		   || ( (length + 4) % block_size))
		{
		  werror("read_packet: Bad packet length %d\n",
			 length);
		  return LSH_FAIL | LSH_DIE;
		}

	      /* Process this block before the length field is lost. */
	      if (closure->connection->rec_mac)
		{
		  UINT8 s[4];
		  WRITE_UINT32(s, closure->sequence_number);
		    
		  HASH_UPDATE(closure->connection->rec_mac, 4, s);
		  HASH_UPDATE(closure->connection->rec_mac,
			      closure->buffer->length,
			      closure->buffer->data);
		}

	      /* Allocate full packet */
	      {
		int done = block_size - 4;
		  
		closure->buffer
		  = ssh_format("%ls%lr",
			       done,
			       closure->buffer->data + 4,
			       length - done,
			       &closure->crypt_pos);

		/* FIXME: Is this needed anywhere? */
		closure->buffer->sequence_number
		  = closure->sequence_number++;

		closure->pos = done;
		closure->state = WAIT_CONTENTS;
	      }
	      /* Fall through */
	    }
	  else
	    /* Try reading some more */
	    break;
	}
      case WAIT_CONTENTS:
	{
	  UINT32 left = closure->buffer->length - closure->pos;
	  int n = A_READ(read, left, closure->buffer->data + closure->pos);

	  switch(n)
	    {
	    case 0:
	      return LSH_OK | LSH_GOON;
	    case A_FAIL:
	      /* Fall through */
	    case A_EOF:
	      /* FIXME: Free associated resources! */
	      return LSH_FAIL | LSH_DIE;
	    }
	  closure->pos += n;
	  total += n;

	  /* Read a complete packet? */
	  if (n == left)
	    {
	      UINT32 left
		= ( (closure->buffer->length + closure->buffer->data)
		    - closure->crypt_pos );
	      if (closure->connection->rec_crypto)
		CRYPT(closure->connection->rec_crypto,
		      left,
		      closure->crypt_pos,
		      closure->crypt_pos);		      
	      if (closure->connection->rec_mac)
		HASH_UPDATE(closure->connection->rec_mac,
			    left,
			    closure->crypt_pos);
	      closure->state = WAIT_MAC;
	      closure->pos = 0;
	      /* Fall through */
	    }
	  else
	    /* Try reading some more */
	    break;
	}
      case WAIT_MAC:
	if (closure->connection->rec_mac)
	  {
	    UINT32 left = (closure->connection->rec_mac->mac_size
			   - closure->pos);
	    UINT8 *mac;
	    
	    int n = A_READ(read, left,
			   closure->recieved_mac->data + closure->pos);

	    switch(n)
	      {
	      case 0:
		return LSH_OK | LSH_GOON;
	      case A_FAIL:
		/* Fall through */
	      case A_EOF:
		/* FIXME: Free associated resources! */
		return LSH_FAIL | LSH_DIE;
	      }
	    closure->pos += n;
	    total += n;
	    
	    /* Read complete mac? */
	    if (n == left)
	      {
		mac = alloca(closure->connection->rec_mac->hash_size);
		HASH_DIGEST(closure->connection->rec_mac, mac);
	    
		if (!memcmp(mac,
			    closure->recieved_mac,
			    closure->connection->rec_mac->hash_size))
		  /* FIXME: Free resources */
		  return LSH_FAIL | LSH_DIE;

		closure->pos += n;
	      }
	    else
	      /* Try reading more */
	      break;
	  }
	/* MAC was ok, send packet on */
	{
	  struct lsh_string *packet = closure->buffer;
	  int res;
	  
	  closure->buffer = NULL;
	  closure->state = WAIT_START;
	  
	  res = A_WRITE(closure->handler, packet);
	  if (LSH_ACTIONP(res))
	    return res;
	  break;
	}
      default:
	fatal("Internal error\n");
      }
  return LSH_OK | LSH_GOON;
}

struct read_handler *make_read_packet(struct abstract_write *handler,
				      struct ssh_connection *connection)
{
  NEW(read_packet, closure);

  closure->super.handler = do_read_packet;

  closure->connection = connection;
  closure->handler = handler;

  closure->state = WAIT_START;
  closure->sequence_number = 0;

  /* closure->pos = 0; */
  closure->buffer = NULL;
  /* closure->crypt_pos = 0; */

  closure->recieved_mac = NULL;
  
  return &closure->super;
}
