/* write_buffer.c
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

#include "write_buffer.h"

#include "xalloc.h"

#include <assert.h>

static int do_write(struct abstract_write **w,
		    struct lsh_string *packet)
{
  struct write_buffer *closure = (struct write_buffer *) *w;
  struct node *new;
  
  MDEBUG(closure);

  if (!packet->length)
    {
      lsh_string_free(packet);
      return LSH_OK | LSH_GOON;
    }

  if (closure->closed)
    {
      lsh_string_free(packet);
      return LSH_FAIL | LSH_CLOSE;
    }
  
  /* Enqueue packet */
  new = xalloc(sizeof(struct node));
  new->packet = packet;
  
  new->next = 0;
  
  if (closure->tail)
    {
      new->prev = closure->tail;
      closure->tail->next = new;
    }
  else
    {
      new->prev = NULL;
      closure->head = new;
    }
  closure->tail = new;

#if 0
  if (closure->try_write)
    {
      /* Attempt writing to the corresponding fd. */
    }
#endif

  closure->empty = 0;

  return LSH_OK | LSH_GOON;
}

/* Copy data as necessary, before writing.
 *
 * FIXME: Writing of large packets could probably be optimized by
 * avoiding copying it into the buffer.
 *
 * Returns 1 if the buffer is non-empty. */
int write_buffer_pre_write(struct write_buffer *buffer)
{
  UINT32 length = buffer->end - buffer->start;

  if (buffer->empty)
    return 0;
  
  if (buffer->start > buffer->block_size)
    {
      /* Copy contents to the start of the buffer */
      memcpy(buffer->buffer, buffer->buffer + buffer->start, length);
      buffer->start = 0;
      buffer->end = length;
    }

  while (length < buffer->block_size)
    {
      /* Copy more data into buffer */
      if (buffer->partial)
	{
	  UINT32 partial_left = buffer->partial->length - buffer->pos;
	  UINT32 buffer_left = 2*buffer->block_size - buffer->end;
	  if (partial_left <= buffer_left)
	    {
	      /* The rest of the partial packet fits in the buffer */
	      memcpy(buffer->buffer + buffer->end,
		     buffer->partial->data + buffer->pos,
		     partial_left);

	      buffer->end += partial_left;
	      length += partial_left;
	      
	      lsh_string_free(buffer->partial);
	      buffer->partial = NULL;
	    }
	  else
	    {
	      memcpy(buffer->buffer + buffer->end,
		     buffer->partial->data + buffer->pos,
		     buffer_left);

	      buffer->end += buffer_left;
	      length += buffer_left;
	      buffer->pos += buffer_left;

	      assert(length >= buffer->block_size);
	    }
	}
      else
	{
	  /* Dequeue a packet, if possible */
	  struct node *n = buffer->head;
	  if (n)
	    {
	      buffer->partial = n->packet;
	      buffer->pos = 0;
	      buffer->head = n->next;
	      if (buffer->head)
		buffer->head->prev = 0;
	      else
		buffer->tail = 0;
	      lsh_free(n);
	    }
	  else
	    break;
	}
    }
  buffer->empty = !length;
  return !buffer->empty;
}

void write_buffer_close(struct write_buffer *buffer)
{
  buffer->closed = 1;
}

struct write_buffer *write_buffer_alloc(UINT32 size)
{
  struct write_buffer *res = xalloc(sizeof(struct write_buffer) - 1 + size*2);
  
  res->super.write = do_write;
  
  res->block_size = size;

  res->empty = 1;
  res->closed = 0;
  
#if 0
  res->try_write = try; 
#endif
  
  res->head = res->tail = 0;

  res->pos = 0;
  res->partial = NULL;

  res->start = res->end = 0;

  return res;
}
