/* read_data.c
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

#include "read_data.h"
#include "werror.h"
#include "xalloc.h"

struct read_data
{
  struct read_handler super; /* Super type */

  UINT32 block_size;

  /* Where to send the data */
  struct abstract_write *handler;

  struct callback *close_callback;
};

static int do_read_data(struct read_handler **h,
			struct abstract_read *read)
{
  struct read_data *closure = (struct read_data *) *h;

  MDEBUG(closure);
  
#if 0
  while(1)
#endif
    {
      struct lsh_string *packet = lsh_string_alloc(closure->block_size);
      int n = A_READ(read, packet->length, packet->data);
      
      switch(n)
	{
	case 0:
	  lsh_string_free(packet);
	  break;
	case A_FAIL:
	  /* Fall through */
	case A_EOF:
	  CALLBACK(closure->close_callback);
	  return LSH_OK | LSH_CLOSE;
	default:
	  {
	    packet->length = n;

	    return A_WRITE(closure->handler, packet);
	  }
	}
    }
  return LSH_OK | LSH_GOON;
}

struct read_handler *make_read_data(struct abstract_write *handler,
				    struct callback *close_callback,
				    UINT32 block_size)
{
  struct read_data *closure;

  NEW(closure);

  closure->super.handler = do_read_data;
  closure->block_size = block_size;

  closure->handler = handler;
  closure->close_callback = close_callback;

  return &closure->super;
}
