/* read_line.c
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

#include <string.h>

#include "read_line.h"
#include "werror.h"
#include "xalloc.h"

struct read_line
{
  struct read_handler super; /* Super type */
  struct line_handler *handler;

  UINT32 pos;   /* Line buffer */
  UINT8 buffer[MAX_LINE];
};

struct string_read
{
  struct abstract_read super;
  struct read_line *line;
  UINT32 index;
};

static int do_string_read(struct abstract_read **r,
			  UINT32 length, UINT8 *buffer)
{
  struct string_read *closure
    = (struct string_read *) *r;
  
  UINT32 left = closure->line->pos - closure->index;
  UINT32 to_read = MIN(length, left);

  MDEBUG(closure);
  
  memcpy(buffer, closure->line->buffer + closure->index, to_read);
  closure->index += to_read;

  return to_read;
}

static int do_read_line(struct read_handler **h,
			struct abstract_read *read)
{
  struct read_line *closure = (struct read_line *) *h;
  
  UINT8 *eol;
  UINT32 length;
  struct read_handler *next;
  int n;

  MDEBUG(closure);
  
  n = A_READ(read, MAX_LINE - closure->pos, closure->buffer);
  
  if (n<0)
    {
      return 0;
    }
  closure->pos += n;

  /* Loop over all recieved lines */
  
  while ( (eol = memchr(closure->buffer, '\n', closure->pos) ))
    {
      /* eol points at the newline character. end points at the
       * character terminating the line, which may be a carriage
       * return preceeding the newline. */
      UINT8 *end = eol;

      if ( (eol > closure->buffer)
	   && (eol[-1] == '\r'))
	end--;
      
      length = end - closure->buffer;
      
      next = PROCESS_LINE(closure->handler, length, closure->buffer);

      {
	/* Remove line from buffer */
	/* Number of characters that have been processed */
	UINT32 done = eol - closure->buffer + 1;
	UINT32 left = closure->pos - done;
	
	memcpy(closure->buffer, closure->buffer + done, left);
	closure->pos = left;
      }

      if (next)
	{
	  /* Read no more lines. Instead, pass remaining data to next,
	   * and return a new read-handler. */
	  if (closure->pos)
	    {
	      struct string_read read =
	      { { STATIC_HEADER do_string_read },
		closure,
		0 };
	      while(next && (read.index < closure->pos))
		if (!READ_HANDLER(next, &read.super))
		  return 0;
	    }
	  /* No data left */
	  lsh_free(closure);
	  *h = next;
	  return 1;
	}
      else
	if (!closure->handler)
	  {
	    /* Fail */
	    return 0;
	  }
    }     
  
  /* Partial line */
  if (closure->pos == MAX_LINE)
    {
      werror("Too long line from server\n");
      return 0;
    }
  return 1;
}

struct read_handler *make_read_line(struct line_handler *handler)
{
  struct read_line *closure = xalloc(sizeof(struct read_line));

  closure->super.handler = do_read_line;
  closure->pos = 0;

  closure->handler = handler;

  return &closure->super;
}

  
