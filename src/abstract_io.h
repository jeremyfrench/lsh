/* abstract_io.h
 *
 * This is the layer separating protocol processing from actual io.
 */

#ifndef LSH_ABSTRACT_IO_H_INCLUDED
#define LSH_ABSTRACT_IO_H_INCLUDED

#include "lsh_types.h"

struct abstract_read;
typedef int (*abstract_read_f)(struct abstract_read *closure,
			       UINT8 *buffer, UINT32 length);
/* A read-function returning n means:
 *
 * n > 0: n bytes were read successfully.
 * n = 0: No more data available, without blocking.
 * n = -1: Read failed.
 * n = -2: EOF.
 */
#define A_FAIL -1
#define A_EOF -2

struct abstract_read
{
  abstract_read_f read;
};

#define A_READ(f, buffer, length) (f)->read((f), (buffer), (length))

struct read_handler
{
  struct read_handler (*handler)(struct read_handler *closure,
				 struct abstract_read *read);
};

#define READ_HANDLER(handler, read) ((handler)->handler((handler), (read)))

/* FIXME: What should writers return? Perhaps a new writer,
 * analogous to read-handlers? */

struct abstract_write;
typedef int (*abstract_write_f)(struct abstract_write *closure,
				struct lsh_string *packet);

struct abstract_write
{
  abstract_write_f write;
};

#endif /*LSH_ABSTRACT_IO_H_INCLUDED */
