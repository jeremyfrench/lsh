/* read_data.c
 *
 *
 *
 * $Id$ */

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
     (super io_consuming_read)
     (vars
       ; For flow control. 
   
       ; FIXME: Perhaps the information that is needed for flow
       ; control should be abstracted out from the channel struct? 

       (channel object ssh_channel)))
*/

static UINT32 do_read_data_query(struct io_consuming_read *s)
{
  CAST(read_data, self, s);
  
  assert(self->channel->sources);
  
  if (self->channel->flags &
      (CHANNEL_RECEIVED_CLOSE | CHANNEL_SENT_CLOSE | CHANNEL_SENT_EOF))
    {
      werror("read_data: Receiving data on closed channel. Ignoring.\n");
      return 0;
    }

  return MIN(self->channel->send_max_packet,
	     self->channel->send_window_size);
}


struct io_read_callback *make_read_data(struct ssh_channel *channel,
					struct abstract_write *write)
{
  NEW(read_data, self);

  init_consuming_read(&self->super, write);
  
  self->super.query = do_read_data_query;
  self->channel = channel;
  self->super.consumer = write;

  channel->sources++;
  
  return &self->super.super;
}

/* FIXME: This function will be obsoleted with the EXC_IO_EOF
 * exception type. It would be better to move the handling to the
 * "consumer" functions in channel.c.*/

/* GABA:
   (class
     (name exc_read_eof_channel_handler)
     (super exception_handler)
     (vars
       (channel object ssh_channel)))
*/

/* FIXME: We have to make sure that this handler is invoked exactly
 * once for each fd attached to the channel. */
static void
do_exc_read_eof_channel_handler(struct exception_handler *s,
				const struct exception *x)
{
  CAST(exc_read_eof_channel_handler, self, s);

  switch(x->type)
    {
    case EXC_IO_EOF:
      {
	CAST_SUBTYPE(io_exception, e, x);

	if (!--self->channel->sources)
	  /* Send eof (but no close). */
	  channel_eof(self->channel);

	close_fd_nicely(e->fd, 0);
      }
      break;
    case EXC_IO_READ:
      {
	CAST_SUBTYPE(io_exception, e, x);

	werror("Read error on fd %i (errno = %i): %z\n",
	       e->fd->fd, e->error, x->msg);

	if (!--self->channel->sources)
	  /* Close channel */
	  channel_close(self->channel);

	break;
      }
	
    default:
      EXCEPTION_RAISE(self->super.parent, x);
    }
}

struct exception_handler *
make_exc_read_eof_channel_handler(struct ssh_channel *channel,
				  struct exception_handler *e)
{
  NEW(exc_read_eof_channel_handler, self);
  self->super.raise = do_exc_read_eof_channel_handler;
  self->super.parent = e;
  
  self->channel = channel;

  return &self->super;
}

				  
