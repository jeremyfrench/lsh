/* read_line.h
 *
 * Read-handler processing a line at a time.
 */

#ifndef  LSH_READ_HANDLER_H_INCLUDED
#define  LSH_READ_HANDLER_H_INCLUDED

#include "abstract_io.h"

/* This limit follows the ssh specification */
#define MAX_LINE 255

#if 0
struct line_handler;

typedef struct read_handler * (*line_handler_f)(struct line_handler *closure,
						UINT32 length,
						UINT8 *line);
#endif

/* May store a new handler into *h. */
struct line_handler
{
  struct read_handler * (*handler)(struct line_handler **h,
				   UINT32 length,
				   UINT8 *line);
};

#define PROCESS_LINE(h, length, line) \
((h)->handler(&(h), (length), (line)))

struct read_line
{
  struct read_handler super; /* Super type */
  struct line_handler *handler;

  UINT32 pos;   /* Line buffer */
  UINT8 buffer[MAX_LINE];
};

struct read_handler *make_read_line(struct line_handler *handler);

#endif /* LSH_READ_HANDLER_H_INCLUDED */
