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

#include <errno.h>
#include <string.h>

#include "read_packet.h"
#include "werror.h"
#include "format.h"
#include "xalloc.h"
#include "io.h"
#include "crypto.h"

#define WAIT_HEADER 0
#define WAIT_CONTENTS 1
#define WAIT_MAC 2

int do_read_packet(struct read_handler **h,
		   struct abstract_read *read)
{
  struct read_packet *closure = (struct read_packet *) *h;

#if 0
  while(1)
    {
#endif
      switch(closure->state)
	{
	case WAIT_HEADER:
	  {
	    UINT32 left = closure->crypto->block_size - closure->pos;
	    int n;
	
	    if (!closure->buffer)
	      {
		closure->buffer
		  = lsh_string_alloc(closure->crypto->block_size);
		closure->pos = 0;
	      }
	    n = A_READ(read, closure->buffer->data + closure->pos, left);
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

	    /* Read a complete block? */
	    if (n == left)
	      {
		UINT32 length;

		CRYPT(closure->crypto,
		      closure->crypto->block_size,
		      closure->buffer->data,
		      closure->buffer->data);

		length = READ_UINT32(closure->buffer->data);
		if (length > closure->max_packet)
		  return 0;

		if ( (length < 12)
		     || (length < (closure->crypto->block_size - 4))
		     || ( (length + 4) % closure->crypto->block_size))
		  return 0;

		/* Process this block before the length field is lost. */
		if (closure->mac)
		  {
		    UINT8 s[4];
		    WRITE_UINT32(s, closure->sequence_number);
		    
		    HASH_UPDATE(closure->mac, 4, s);
		    HASH_UPDATE(closure->mac,
				closure->buffer->length,
				closure->buffer->data);
		  }

		/* Allocate full packet */
		closure->buffer = ssh_format("%ls%lr",
					     closure->crypto->block_size - 4,
					     closure->buffer->data + 4,
					     length, &closure->crypt_pos);

		/* FIXME: Is this needed anywhere? */
		closure->buffer->sequence_number = closure->sequence_number++;

		closure->pos = 4;
		closure->state = WAIT_CONTENTS;
		/* Fall through */
	      }
	    else
	      /* Try reading some more */
	      break;
	  }
	case WAIT_CONTENTS:
	  {
	    UINT32 left = closure->buffer->length - closure->pos;
	    int n = A_READ(read, closure->buffer->data + closure->pos, left);

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
		CRYPT(closure->crypto,
		      closure->buffer->length - closure->crypt_pos,
		      closure->buffer->data + closure->crypt_pos,
		      closure->buffer->data + closure->crypt_pos);		      

		if (closure->mac)
		  {
		    HASH_UPDATE(closure->mac,
			   closure->buffer->length - closure->crypt_pos,
			   closure->buffer->data + closure->crypt_pos);
		    HASH_DIGEST(closure->mac,
			   closure->computed_mac);
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
	  if (closure->mac->mac_size)
	    {
	      UINT32 left = closure->mac->mac_size - closure->pos;
	      UINT8 *mac = alloca(left);

	      int n = A_READ(read, mac, left);

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

	      if (!memcpy(mac,
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
	  if (A_WRITE(closure->handler, closure->buffer) != WRITE_OK)
	    /* FIXME: What now? */
	    return 0;
	  
	  closure->buffer = NULL;
	  closure->state = WAIT_HEADER;
	  break;
	  
	default:
	  fatal("Internal error\n");
	}
#if 0
    }
#endif
}

struct read_handler *make_read_packet(struct abstract_write *handler,
				      UINT32 max_packet)
{
  struct read_packet *closure = xalloc(sizeof(struct read_packet));

  closure->super.handler = do_read_packet;

  closure->state = WAIT_HEADER;
  closure->max_packet = max_packet;
  closure->sequence_number = 0;

  /* closure->pos = 0; */
  closure->buffer = NULL;
  /* closure->crypt_pos = 0; */

  closure->mac = 0;
  closure->crypto = &crypto_none_instance;

  closure->handler = handler;

  return &closure->super;
}
