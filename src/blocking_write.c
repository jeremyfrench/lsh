/* blocking_write.c
 *
 * $id:$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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

#include "blocking_write.h"

#include "io.h"
#include "xalloc.h"

/* CLASS:
   (class
     (name blocking_write)
     (super abstract_write)
     (vars
       (fd . int)
       (write . (pointer (function int int UINT32 "UINT8 *")))))
*/

#include "blocking_write.c.x"

static int do_blocking_write(struct abstract_write *w,
			     struct lsh_string *packet)
{
  CAST(blocking_write, closure, w);
  int success = closure->write(closure->fd, packet->length, packet->data);

  lsh_string_free(packet);

  return success ? LSH_OK : LSH_FAIL | LSH_DIE; 
}

struct abstract_write *make_blocking_write(int fd, int with_nonblocking)
{
  NEW(blocking_write, closure);

  closure->super.write = do_blocking_write;
  closure->write = (with_nonblocking ? write_raw_with_poll : write_raw);
  closure->fd = fd;

  return &closure->super;
}
