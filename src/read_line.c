/* read_line.c
 *
 */

#include <string.h>

#include "read_line.h"
#include "werror.h"
#include "xalloc.h"

struct string_read
{
  struct abstract_read super;
  struct read_line *line;
  UINT32 index;
};

static int do_string_read(struct abstract_read **r,
			  UINT8 *buffer, UINT32 length)
{
  struct string_read *closure
    = (struct string_read *) *r;
  
  UINT32 left = closure->line->pos - closure->index;
  UINT32 to_read = MIN(length, left);

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

  int n = A_READ(read, closure->buffer, MAX_LINE - closure->pos);
  
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
	      { { do_string_read },
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

  
