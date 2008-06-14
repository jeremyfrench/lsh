/* gateway_x11.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2008 Niels Möller
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

#include "gateway.h"

#include "channel.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#if WITH_X11_FORWARD

/* X11 related functions */

static void
do_gateway_x11_open(struct client_x11_handler *s,
		    const struct channel_open_info *info,
		    struct simple_buffer *args)
{
  CAST(gateway_x11_handler, self, s);

  trace("do_gateway_x11_open\n");

  if (self->gateway->pending_close)
    /* We are waiting for channels to close. Don't open any new ones. */
    channel_open_deny(info, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
		      "Waiting for channels to close.");
  else
    {
      uint32_t arg_length;
      const uint8_t *arg;

      parse_rest(args, &arg_length, &arg);

      if (!gateway_forward_channel_open(self->gateway,
					info, arg_length, arg))
	channel_open_deny(info, SSH_OPEN_RESOURCE_SHORTAGE,
			  "Too many channels.");
    }
}

static struct gateway_x11_handler *
make_gateway_x11_handler(struct ssh_connection *gateway, int single_connection,
			 int pending)
{
  NEW(gateway_x11_handler, self);
  init_resource(&self->super.super, NULL);
  self->super.single_connection = single_connection;
  self->super.open = do_gateway_x11_open;
  self->pending = pending;
  self->gateway = gateway;

  return self;
}

DEFINE_CHANNEL_REQUEST(gateway_x11_request_handler)
	(struct channel_request *s UNUSED,
	 struct ssh_channel *c,
	 const struct request_info *info,
	 struct simple_buffer *buffer)
{
  CAST(gateway_channel, self, c);

  unsigned single;
  if (parse_uint8(buffer, &single))
    {
      /* Require want reply, so we know if we want CHANNEL_OPEN "x11"
	 requests. */
      if (self->chain->x11 || !info->want_reply)
	{
	  werror("Denying x11 forwarding request via gateway.\n");
	  channel_request_reply(&self->super, info, 0);
	}
      else
	{
	  uint32_t arg_length;
	  const uint8_t *arg;
	  
	  parse_rest(buffer, &arg_length, &arg);

	  self->chain->x11
	    = make_gateway_x11_handler(self->super.connection, single,
				       self->chain->super.pending_requests);
	  remember_resource(self->connection, &self->chain->x11->super.super);
	  
	  channel_send_request(&self->chain->super,
			       info->type_length, info->type_data,
			       info->want_reply,
			       "%c%ls", single, arg_length, arg);
	}
    }
  else
    SSH_CONNECTION_ERROR(self->super.connection, "Invalid x11 request.");
}

#endif /* WITH_X11_FORWARD */
