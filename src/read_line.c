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

static int do_string_read(struct string_read *closure,
			  UINT8 *buffer, UINT32 length)
{
  UINT32 left = closure->line->pos - closure->index;
  UINT32 to_read = MIN(length, left);

  memcpy(buffer, closure->line->buffer + closure->index, to_read);
  closure->index += to_read;

  return to_read;
}

static struct read_handler *do_read_line(struct read_line *closure,
					 struct abstract_read *read)
{
  int n = A_READ(read, closure->buffer, MAX_LINE - closure->pos);
  UINT8 *eol;
  UINT32 length;
  struct read_handler *next;
  
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
      
      if (!next)
	{
	  /* Read another line */
	  /* Number of characters that have been processed */
	  UINT32 done = eol - closure->buffer + 1;
	  UINT32 left = closure->pos - done;

	  memcpy(closure->buffer, closure->buffer + done, left);
	  closure->pos = left;
	}
      else
	{
	  /* Read no more lines. Instead, pass remaining data to next,
	   * and return a new read-handler. */
	  if (closure->pos)
	    {
	      struct string_read read =
	      { { (abstract_read_f) do_string_read },
		closure,
		0 };
	      while(next && (read.index < closure->pos))
		next = READ_HANDLER(next, &read.super);
	    }
	  /* No data left */
	  free(closure);
	  return next;
	}
    }
  
  /* Partial line */
  if (closure->pos == MAX_LINE)
    {
      werror("Too long line from server\n");
      return NULL;
    }
  return &(closure->super);
}

struct read_handler *make_read_line(struct line_handler *handler)
{
  struct read_line *closure = xalloc(sizeof(struct read_line));

  closure->super.handler = (read_handler_f) do_read_line;
  closure->pos = 0;

  closure->handler = handler;

  return (struct read_handler *) closure;
}

  
