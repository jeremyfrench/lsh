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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "read_data.h"

#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "read_data.c.x"

/* GABA:
   (class
     (name read_data)
     (super read_handler)
     (vars
       ; Where to send the data 
       (write object abstract_write)

       ; For flow control. 
   
       ; FIXME: Perhaps the information that is needed for flow
       ; control should be abstracted out from the channel struct? 

       (channel object ssh_channel)))
*/

static int do_read_data(struct read_handler **h,
			struct abstract_read *read)
{
  CAST(read_data, closure, *h);
  int to_read;
  int n;
  struct lsh_string *packet;
  
  assert(closure->channel->sources);
  
  if (closure->channel->flags &
      (CHANNEL_RECEIVED_CLOSE | CHANNEL_SENT_CLOSE | CHANNEL_SENT_EOF))
    return LSH_FAIL | LSH_DIE;

  to_read = MIN(closure->channel->send_max_packet,
		closure->channel->send_window_size);

  if (!to_read)
    {
      /* Stop reading */
      return LSH_OK | LSH_HOLD;
    }
  
  packet = lsh_string_alloc(to_read);
  n = A_READ(read, to_read, packet->data);

  switch(n)
    {
    case 0:
      lsh_string_free(packet);
      return LSH_OK | LSH_GOON;
    case A_FAIL:
      /* Send a channel close, and prepare the channel for closing */      
      return channel_close(closure->channel)
	| LSH_FAIL | LSH_DIE;
    case A_EOF:
      if (!--closure->channel->sources)
	/* Send eof (but no close). */
	channel_eof(closure->channel);
      return LSH_OK | LSH_DIE;
    default:
      packet->length = n;

      /* FIXME: Should we consider the error code here? Probably not;
       * an error here means that the fd connected to the channel will be closed.
       * Cleaning up the channel itself should be taken care of later. */
      return A_WRITE(closure->write, packet);
    }
}

struct read_handler *make_read_data(struct ssh_channel *channel,
				    struct abstract_write *write)
{
  NEW(read_data, closure);

  closure->super.handler = do_read_data;
  closure->channel = channel;
  closure->write = write;

  channel->sources++;
  
  return &closure->super;
}
