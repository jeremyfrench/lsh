/* read_packet.c
 *
 *
 *
 * $Id$ */

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
  struct lsh_string *computed_mac; 

  struct abstract_write *handler;
  struct ssh_connection *connection;
};

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
    
static int do_read_packet(struct read_handler **h,
			  struct abstract_read *read)
{
  struct read_packet *closure = (struct read_packet *) *h;

  MDEBUG(closure);
  
#if 0
  while(1)
    {
#endif
      switch(closure->state)
	{
	case WAIT_START:
	  {
	    UINT32 block_size = closure->connection->rec_crypto
	      ? closure->connection->rec_crypto->block_size : 8;

	    closure->buffer = lsh_string_realloc(closure->buffer,
						 block_size);
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
		return 1;
	      case A_FAIL:
		/* Fall through */
	      case A_EOF:
		/* FIXME: Free associated resources! */
		return 0;
	      }
	    closure->pos += n;

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
		    return 0;
		  }

		if ( (length < 12)
		     || (length < (block_size - 4))
		     || ( (length + 4) % block_size))
		  {
		    werror("read_packet: Bad packet length %d\n",
			   length);
		    return 0;
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
		return 1;
	      case A_FAIL:
		werror("do_read_packet: read() failed, %s\n", strerror(errno));
		/* Fall through */
	      case A_EOF:
		/* FIXME: Free associated resources! */
		return 0;
	      }
	    closure->pos += n;

	    /* Read a complete packet? */
	    if (n == left)
	      {
		assert(left == ((closure->buffer->length
				 + closure->buffer->data)
				- closure->crypt_pos));
		if (closure->connection->rec_crypto)
		  CRYPT(closure->connection->rec_crypto,
			left,
			closure->crypt_pos,
			closure->crypt_pos);		      
		if (closure->connection->rec_mac)
		  {
		    closure->computed_mac = lsh_string_realloc
		      (closure->computed_mac,
		       closure->connection->rec_mac->hash_size);

		    HASH_UPDATE(closure->connection->rec_mac,
				left,
				closure->crypt_pos);
		    HASH_DIGEST(closure->connection->rec_mac,
				closure->computed_mac->data);
		  }
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
	      UINT8 *mac = alloca(left);

	      int n = A_READ(read, left, mac);

	      switch(n)
		{
		case 0:
		  return 1;
		case A_FAIL:
		  werror("do_read_packet: read() failed, %s\n",
			 strerror(errno));
		  /* Fall through */
		case A_EOF:
		  /* FIXME: Free associated resources! */
		  return 0;
	      }

	      /* FIXME: Don't fail until the entire MAC has been read.
	       * Otherwise we will leak information about partially
	       * correct MAC:s. */
	      if (!memcmp(mac,
			  closure->computed_mac + closure->pos,
			  n))
		/* FIXME: Free resources */
		return 0;

	      closure->pos += n;

	      if (n < left)
		/* Try reading more */
		break;
	    }
	  /* MAC was ok, send packet on */
	  if (A_WRITE(closure->handler, closure->buffer)
	      != WRITE_OK)
	    /* FIXME: What now? */
	    return 0;
	  
	  closure->buffer = NULL;
	  closure->state = WAIT_START;
	  break;
	  
	default:
	  fatal("Internal error\n");
	}
#if 0
    }
#endif
  return 1;
}

struct read_handler *make_read_packet(struct abstract_write *handler,
				      struct ssh_connection *connection)
{
  struct read_packet *closure = xalloc(sizeof(struct read_packet));

  closure->super.handler = do_read_packet;

  closure->connection = connection;
  closure->handler = handler;

  closure->state = WAIT_START;
  closure->sequence_number = 0;

  /* closure->pos = 0; */
  closure->buffer = NULL;
  /* closure->crypt_pos = 0; */

  closure->computed_mac = NULL;
  
  return &closure->super;
}
