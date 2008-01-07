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

#include "gateway_channel.c.x"

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

/* This is a channel one of a pair of channels that are connected
   together. */
/* GABA:
   (class
     (name gateway_channel)
     (super ssh_channel)
     (vars
       ;; Put local_channel_number here?
       (chain object ssh_channel)))
*/

static void
do_kill_gateway_channel(struct resource *s)
{
  CAST(gateway_channel, self, s);
  if (self->super.super.alive)
    {
      trace("do_kill_gateway_channel\n");
      self->super.super.alive = 0;

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
      channel_transmit_data(self->chain, length, data);
      
      break;
    case CHANNEL_STDERR_DATA:
      channel_transmit_extended(self->chain, SSH_EXTENDED_DATA_STDERR,
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
    channel_adjust_rec_window(self->chain, i);
}

static void
do_gateway_channel_event(struct ssh_channel *c, enum channel_event event)
{
  CAST(gateway_channel, self, c);

  switch(event)
    {
    case CHANNEL_EVENT_CONFIRM:
      if (!self->chain->connection->super.alive)
	{
	  /* The other channel has disappeared, so close. */
	  channel_close(&self->super);
	}
      else
	{
	  /* This method is invoked on the target channel. Propagate
	     the target channel's send variables to the originating
	     channel's receive variables. */
	  self->chain->rec_window_size = self->super.send_window_size;
	  self->chain->rec_max_packet = self->super.send_max_packet;

	  self->super.receive = do_receive;
	  self->super.send_adjust = do_send_adjust;

	  self->chain->receive = do_receive;
	  self->chain->send_adjust = do_send_adjust;

	  ssh_connection_activate_channel(self->chain->connection,
					  self->chain->local_channel_number);
	  remember_resource(self->super.connection->resources,
			    &self->super.super);
	  
	  /* We don't pass on any additional arguments. */
	  SSH_CONNECTION_WRITE(self->chain->connection,
			       format_open_confirmation(self->chain,
							""));
	}
      break;
    case CHANNEL_EVENT_DENY:
      /* This method is invoked on the target channel. We need to tear
	 down the originating channel. */
      if (self->chain->connection->super.alive)
	{
	  /* FIXME: We should propagate the error code and message
	     over the gateway. */
	  SSH_CONNECTION_WRITE(self->chain->connection,
			       format_open_failure(self->chain->remote_channel_number,
						   SSH_OPEN_RESOURCE_SHORTAGE,
						   "Refused by server", ""));

	  ssh_connection_dealloc_channel(self->chain->connection,
					 self->chain->local_channel_number);
	}
      break;
    case CHANNEL_EVENT_EOF:
      channel_eof(self->chain);
      break;

    case CHANNEL_EVENT_CLOSE:
      channel_close(self->chain);
      break;

    case CHANNEL_EVENT_STOP:
    case CHANNEL_EVENT_START:
      /* FIXME: Ignore? The entire gateway has to be stopped and
	 started anyway. */
      break;
    }      
}  

static void
do_gateway_channel_request(struct ssh_channel *c,
			   const struct channel_request_info *info,
			   struct simple_buffer *buffer)
{
  CAST(gateway_channel, self, c);
  uint32_t arg_length;
  const uint8_t *arg;

  parse_rest(buffer, &arg_length, &arg);

  /* FIXME: Use a format_channel_request function. */
  SSH_CONNECTION_WRITE(self->chain->connection,
		       ssh_format("%c%i%s%c%ls",
				  SSH_MSG_CHANNEL_REQUEST,
				  self->chain->remote_channel_number,
				  info->type_length, info->type_data,
				  info->want_reply,
				  arg_length, arg));
}

static void
do_gateway_channel_success(struct ssh_channel *c)
{
  CAST(gateway_channel, self, c);

  SSH_CONNECTION_WRITE(self->chain->connection,
		       format_channel_success(self->chain->remote_channel_number));
}

static void
do_gateway_channel_failure(struct ssh_channel *c)
{
  CAST(gateway_channel, self, c);

  SSH_CONNECTION_WRITE(self->chain->connection,
		       format_channel_failure(self->chain->remote_channel_number));
}

static struct channel_request_methods
gateway_request_methods =
{
  do_gateway_channel_request,
  do_gateway_channel_success,
  do_gateway_channel_failure
};
  
static int
make_gateway_pair(struct gateway_connection *connection,
		  struct channel_open_info *info,
		  uint32_t arg_length, const uint8_t *arg)
{
  int origin_local_number;

  origin_local_number
    = ssh_connection_alloc_channel(&connection->super,
				   CHANNEL_ALLOC_RECEIVED_OPEN);

  if (origin_local_number < 0)
    return 0;
  else
    {
      NEW(gateway_channel, origin);
      NEW(gateway_channel, target);

      init_channel(&origin->super,
		   do_kill_gateway_channel, do_gateway_channel_event);
      init_channel(&target->super,
		   do_kill_gateway_channel, do_gateway_channel_event);

      origin->super.request_methods = &gateway_request_methods;
      target->super.request_methods = &gateway_request_methods;

      origin->chain = &target->super;
      target->chain = &origin->super;

      origin->super.send_max_packet = info->send_max_packet;
      origin->super.send_window_size = info->send_window_size;
      origin->super.remote_channel_number = info->remote_channel_number;
      
      target->super.rec_max_packet = origin->super.send_max_packet;
      target->super.rec_window_size = origin->super.send_window_size;

      /* Prevents the processing when sending and receiving CHANNEL_EOF from
	 closing the channel. */
      origin->super.sinks++;
      target->super.sinks++;
      
      if (!channel_open_new_type(connection->shared,
				 &target->super,
				 info->type_length, info->type_data,
				 "%ls", arg_length, arg))
	{
	  ssh_connection_dealloc_channel(&connection->super,
					 origin_local_number);
	  return 0;
	}
      ssh_connection_register_channel(&connection->super,
				      origin_local_number,
				      &origin->super);

      return 1;
    }
}

static void
gateway_handle_channel_open(struct gateway_connection *connection,
			    uint32_t length, const uint8_t *packet)
{
  struct simple_buffer buffer;
  struct channel_open_info info;
    
  trace("gateway_handle_channel_open\n");

  simple_buffer_init(&buffer, length, packet);
  
  if (parse_string(&buffer, &info.type_length, &info.type_data)
      && parse_uint32(&buffer, &info.remote_channel_number)
      && parse_uint32(&buffer, &info.send_window_size)
      && parse_uint32(&buffer, &info.send_max_packet))
    {
      uint32_t arg_length;
      const uint8_t *arg;

      trace("gateway_handle_channel_open: send_window_size = %i\n",
	    info.send_window_size);

      parse_rest(&buffer, &arg_length, &arg);
      
      /* We don't support larger packets than the default,
       * SSH_MAX_PACKET. */
      if (info.send_max_packet > SSH_MAX_PACKET)
	{
	  werror("handle_gateway_channel_open: The gateway asked for really large packets.\n");
	  info.send_max_packet = SSH_MAX_PACKET;
	}
      
      if (connection->shared->pending_close)
	{
	  /* We are waiting for channels to close. Don't open any new ones. */

	  SSH_CONNECTION_WRITE(&connection->super,
			       format_open_failure(
				 info.remote_channel_number,
				 SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
				 "Waiting for channels to close.", ""));
	}
      else if (!make_gateway_pair(connection, &info,
				  arg_length, arg))
	{
	  SSH_CONNECTION_WRITE(&connection->super,
			       format_open_failure(
				 info.remote_channel_number,
				 SSH_OPEN_RESOURCE_SHORTAGE,
				 "Too many channels.", ""));
	}
    }
  else
    SSH_CONNECTION_ERROR(&connection->super,
			 "Invalid SSH_MSG_CHANNEL_OPEN message.");
}

int
gateway_packet_handler(struct gateway_connection *connection,
		       uint32_t length, const uint8_t *packet)
{
  assert(length > 0);

  switch (packet[0])
    {
      /* FIXME: When using local numbers like this, we must make sure
	 to reject requests arriving over the network. */
    case SSH_LSH_GATEWAY_STOP:
      /* The correct behaviour is to kill the port object. */
      fatal("Not implemented.\n");
      
    case SSH_MSG_CHANNEL_OPEN:
      gateway_handle_channel_open(connection, length - 1, packet + 1);
      break;

    default:
      return channel_packet_handler(&connection->super, length, packet);
    }
  return 1;
}
