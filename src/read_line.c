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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <assert.h>
#include <string.h>

#include "read_line.h"

#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "read_line.h.x"
#undef GABA_DEFINE

#include "read_line.c.x"

/* GABA:
   (class
     (name read_line)
     (super read_handler)
     (vars
       (handler object line_handler)

       ; Line buffer       
       (pos simple UINT32)
       (buffer array UINT8 MAX_LINE)))
*/

/* GABA:
   (class
     (name string_read)
     (super abstract_read)
     (vars
       (line object read_line)
       (index simple UINT32)))
*/

static int do_string_read(struct abstract_read **r,
			  UINT32 length, UINT8 *buffer)
{
  CAST(string_read, closure, *r);
  
  UINT32 left = closure->line->pos - closure->index;
  UINT32 to_read = MIN(length, left);

  memcpy(buffer, closure->line->buffer + closure->index, to_read);
  closure->index += to_read;

  return to_read;
}

static int do_read_line(struct read_handler **h,
			struct abstract_read *read)
{
  CAST(read_line, closure, *h);
  
  UINT8 *eol;
  UINT32 length;
  struct read_handler *next = NULL;
  int n;

  assert(MAX_LINE - closure->pos > 0);
  n = A_READ(read, MAX_LINE - closure->pos, closure->buffer);

  switch(n)
    {
    case 0:
      return LSH_OK | LSH_GOON;
    case A_FAIL:
      /* Fall throw */
    case A_EOF:
      /* FIXME: Free associated resources! */
      return LSH_FAIL | LSH_DIE;
    }

  closure->pos += n;

  /* Loop over all received lines */
  
  while ( (eol = memchr(closure->buffer, '\n', closure->pos) ))
    {
      /* eol points at the newline character. end points at the
       * character terminating the line, which may be a carriage
       * return preceeding the newline. */
      UINT8 *end = eol;
      int res;
      
      if ( (eol > closure->buffer)
	   && (eol[-1] == '\r'))
	end--;
      
      length = end - closure->buffer;
      
      res = PROCESS_LINE(closure->handler, &next, length, closure->buffer);
      {
	/* Remove line from buffer */
	/* Number of characters that have been processed */
	UINT32 done = eol - closure->buffer + 1;
	UINT32 left = closure->pos - done;
	
	memcpy(closure->buffer, closure->buffer + done, left);
	closure->pos = left;
      }

      if (LSH_CLOSEDP(res))
	return res;
      
      if (next)
	{
	  /* Read no more lines. Instead, pass remaining data to next,
	   * and install the new read-handler. */
	  if (closure->pos)
	    {
	      int res;
	      
	      struct string_read read =
	      { { STACK_HEADER, do_string_read },
		closure,
		0 };
	      while(next && (read.index < closure->pos))
		{
		  res = READ_HANDLER(next, &read.super);
		  if (LSH_CLOSEDP(res))
		    return res;
		}
	    }
	  /* No data left */
	  KILL(closure);
	  *h = next;
	  return LSH_OK | LSH_GOON;
	}
      else
	if (!closure->handler)
	  {
	    /* Fail */
	    return LSH_FAIL | LSH_DIE;
	  }
    }     
  
  /* Partial line */
  if (closure->pos == MAX_LINE)
    {
      werror("Received too long a line\n");
      return LSH_FAIL | LSH_DIE;
    }
  return LSH_OK | LSH_GOON;
}

struct read_handler *make_read_line(struct line_handler *handler)
{
  NEW(read_line, closure);

  closure->super.handler = do_read_line;
  closure->pos = 0;

  closure->handler = handler;

  return &closure->super;
}

  
