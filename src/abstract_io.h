/* abstract_io.h
 *
 * This is the layer separating protocol processing from actual io.
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

#ifndef LSH_ABSTRACT_IO_H_INCLUDED
#define LSH_ABSTRACT_IO_H_INCLUDED

#include "lsh_types.h"

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
  struct lsh_object header;
  int (*read)(struct abstract_read **r,
	      UINT32 length, UINT8 *buffer);
};

#define A_READ(f, length, buffer) (f)->read(&(f), (length), (buffer))


/* May store a new handler into *h. */
struct read_handler
{
  struct lsh_object header;
  int (*handler)(struct read_handler **h,
		 struct abstract_read *read);
};

#define READ_HANDLER(h, read) ((h)->handler(&(h), (read)))

/* May store a new handler into *w. FIXME: Is this indirection ever
 * used? */
struct abstract_write
{
  struct lsh_object header;
  int (*write)(struct abstract_write **w,
	       struct lsh_string *packet);
};

#define A_WRITE(f, packet) ((f)->write(&(f), (packet)))

/* A handler that passes packets on to another processor */
struct abstract_write_pipe
{
  struct abstract_write super;
  struct abstract_write *next;
};

#endif /*LSH_ABSTRACT_IO_H_INCLUDED */
