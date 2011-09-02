/* gateway_channel.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "gateway.h"

#include "channel.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

/* A pair of gateway_channel objects are chained together so that
 * requests and data received on one of the channels are directed to
 * the other.
 *
 * Chaining happens as follows:
 *
 * 1. First a CHANNEL_OPEN request is received on one connection, and
 *    a channel object is created. We refer to this object as the
 *    _originating_ channel.
 *
 * 2. Next, we send a similar CHANNEL_OPEN request on some other
 *    connection, and create a channel object referred to as the
 *    _target_ channel.
 *
 * 3. When we receive a reply to the CHANNEL_OPEN request sent in (2),
 *    we chain the two channel objects together, and reply to the
 *    CHANNEL_OPEN request we received in (1). */

static void
do_kill_gateway_channel(struct resource *s)
{
  CAST(gateway_channel, self, s);
  if (self->super.super.alive)
    {
      trace("do_kill_gateway_channel\n");
      self->super.super.alive = 0;

      if (self->x11)
	KILL_RESOURCE(&self->x11->super.super);

      /* NOTE: We don't attempt to close or kill self->chain (since it
	 may not yet be active). Instead, we leave to the connection's
	 kill method handler to initiate close of all active
	 channels. */
    }
}

static void
do_receive(struct ssh_channel *c,
	   int type,
	   uint32_t length, const uint8_t *data)
{
  CAST(gateway_channel, self, c);

  switch(type)
    {
    case CHANNEL_DATA:
      channel_transmit_data(&self->chain->super, length, data);
      
      break;
    case CHANNEL_STDERR_DATA:
      channel_transmit_extended(&self->chain->super, SSH_EXTENDED_DATA_STDERR,
				length, data);
      break;
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static void
do_send_adjust(struct ssh_channel *s,
               uint32_t i)
{
  CAST(gateway_channel, self, s);
  if (i)
    channel_adjust_rec_window(&self->chain->super, i);
}

static void
do_gateway_channel_event(struct ssh_channel *c, enum channel_event event)
{
  CAST(gateway_channel, self, c);

  switch(event)
    {
    case CHANNEL_EVENT_CONFIRM:
      if (!self->info->connection->super.alive)
        {
          /* The other channel has disappeared, so close. */
          channel_close(&self->super);
        }
      else
        {
          /* This method is invoked on the target channel. Propagate
             the target channel's send variables to the originating
             channel's receive variables. */
          self->chain->super.rec_window_size = self->super.send_window_size;
          self->chain->super.rec_max_packet = self->super.send_max_packet;

          self->super.receive = do_receive;
          self->super.send_adjust = do_send_adjust;

          self->chain->super.receive = do_receive;
          self->chain->super.send_adjust = do_send_adjust;

	  channel_open_confirm(self->info, &self->chain->super);
        }
      break;
    case CHANNEL_EVENT_DENY:
      /* This method is invoked on the target channel. We need to tear
         down the originating channel. */
      if (self->info->connection->super.alive)
        {
          /* FIXME: We should propagate the error code and message
             over the gateway. */
	  channel_open_deny(self->info, SSH_OPEN_RESOURCE_SHORTAGE,
			    "Refused by server");
        }
      break;
    case CHANNEL_EVENT_EOF:
      channel_eof(&self->chain->super);
      break;

    case CHANNEL_EVENT_CLOSE:
      /* FIXME: Can we arrange so that the gateway connection is
	 closed if pending_close on the sared connection is set, and
	 the last channel is closed. */
      channel_close(&self->chain->super);
      break;

    case CHANNEL_EVENT_SUCCESS:
      if (self->x11 && self->x11->pending)
	{
	  if (!--self->x11->pending)
	    {
	      CAST(client_connection, connection, self->super.connection);
	      client_add_x11_handler(connection, &self->x11->super);
	    }
	}

      SSH_CONNECTION_WRITE(self->chain->super.connection,
			   format_channel_success(self->chain->super.remote_channel_number));
      break;

    case CHANNEL_EVENT_FAILURE:
      if (self->x11 && self->x11->pending)
	{
	  if (!--self->x11->pending)
	    {
	      KILL_RESOURCE(&self->x11->super.super);
	      self->x11 = NULL;
	    }
	}
      
      SSH_CONNECTION_WRITE(self->chain->super.connection,
			   format_channel_failure(self->chain->super.remote_channel_number));
      break;
      
    case CHANNEL_EVENT_STOP:
    case CHANNEL_EVENT_START:
      /* Ignore. The channel doesn't do any i/o of its own, so flow
	 control must be handled elsewhere. */
      break;
    }      
}  

DEFINE_CHANNEL_REQUEST(gateway_forward_channel_request)
	(struct channel_request *s UNUSED,
	 struct ssh_channel *c,
	 const struct request_info *info,
	 struct simple_buffer *buffer)
{
  CAST(gateway_channel, self, c);
  uint32_t arg_length;
  const uint8_t *arg;

  parse_rest(buffer, &arg_length, &arg);

  channel_send_request(&self->chain->super,
		       info->type_length, info->type_data,
		       info->want_reply,
		       "%ls", arg_length, arg);
}

int
gateway_forward_channel_open(struct ssh_connection *target_connection,
			     const struct channel_open_info *info,
			     uint32_t arg_length, const uint8_t *arg)
{
  NEW(gateway_channel, origin);
  NEW(gateway_channel, target);

  init_channel(&origin->super,
	       do_kill_gateway_channel, do_gateway_channel_event);
  init_channel(&target->super,
	       do_kill_gateway_channel, do_gateway_channel_event);

#if WITH_X11_FORWARD
  origin->super.request_types = make_alist(1,
					   ATOM_X11_REQ, &gateway_x11_request_handler,
					   -1);
#endif
  origin->super.request_fallback = &gateway_forward_channel_request;
  target->super.request_fallback = &gateway_forward_channel_request;

  origin->chain = target;
  target->chain = origin;

  origin->info = NULL;
  target->info = info;

  target->super.rec_max_packet = info->send_max_packet;
  target->super.rec_window_size = info->send_window_size;

  /* Prevents the processing when sending and receiving CHANNEL_EOF from
     closing the channel. */
  origin->super.sinks++;
  target->super.sinks++;

  return channel_open_new_type(target_connection,
			       &target->super,
			       info->type_length, info->type_data,
			       "%ls", arg_length, arg);
}

/* Used for all channel open requests sent to the gateway. I.e., the
   target connection is the shared one. */
DEFINE_CHANNEL_OPEN(gateway_channel_open)
	(struct channel_open *s UNUSED,
	 const struct channel_open_info *info,
	 struct simple_buffer *args)
{
  CAST(gateway_connection, connection, info->connection);
  trace("gateway_channel_open\n");

  trace("gateway_channel_open: send_window_size = %i\n",
	info->send_window_size);

  if (connection->shared->super.pending_close)
    /* We are waiting for channels to close. Don't open any new ones. */
    channel_open_deny(info, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
		      "Waiting for channels to close.");
  else
    {
      uint32_t arg_length;
      const uint8_t *arg;

      parse_rest(args, &arg_length, &arg);

      if (!gateway_forward_channel_open(&connection->shared->super,
					info, arg_length, arg))
	channel_open_deny(info, SSH_OPEN_RESOURCE_SHORTAGE,
			  "Too many channels.");
    }
}
