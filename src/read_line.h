/* read_line.h
 *
 * Read-handler processing a line at a time.
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

#ifndef  LSH_READ_HANDLER_H_INCLUDED
#define  LSH_READ_HANDLER_H_INCLUDED

#include "abstract_io.h"

#define CLASS_DECLARE
#include "read_line.h.x"
#undef CLASS_DECLARE

/* This limit follows the ssh specification */
#define MAX_LINE 255

/* May store a new handler into *h. */
/* CLASS:
   (class
     (name line_handler)
     (vars
       (handler indirect-method "struct read_handler *"
		"UINT32 length" "UINT8 *line")))
*/

#if 0
struct line_handler
{
  struct lsh_object header;
  
  struct read_handler * (*handler)(struct line_handler **h,
				   UINT32 length,
				   UINT8 *line);
};
#endif

#define PROCESS_LINE(h, length, line) \
((h)->handler(&(h), (length), (line)))

struct read_handler *make_read_line(struct line_handler *handler);

#endif /* LSH_READ_HANDLER_H_INCLUDED */
