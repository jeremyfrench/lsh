/* read_line.h
 *
 * Read-handler processing a line at a time.
 */

#ifndef  LSH_READ_HANDLER_H_INCLUDED
#define  LSH_READ_HANDLER_H_INCLUDED

#include "abstract_io.h"

/* This limit follows the ssh specification */
#define MAX_LINE 255

struct line_handler;

typedef struct read_handler * (*line_handler_f)(struct line_handler *closure,
						UINT32 length,
						UINT8 *line);
struct line_handler
{
  line_handler_f handler;
};

#define PROCESS_LINE(h, length, line) \
((h)->handler((h), (length), (line)))

struct read_line
{
  struct read_handler super; /* Super type */

  UINT32 pos;   /* Line buffer */
  UINT8 buffer[MAX_LINE];

  struct line_handler *handler;
};

struct read_handler *make_read_line(struct line_handler *handler);

#endif /* LSH_READ_HANDLER_H_INCLUDED */
