/* server_tcpforward.c
 *
 * Server side of tcpip forwarding.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Balázs Scheidler, Niels Möller
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

#include "tcpforward.h"

#include "channel_forward.h"
#include "exception.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

/* Forward declarations */
/* FIXME: Should be static */
struct command_3 open_forwarded_tcpip_command;
#define OPEN_FORWARDED_TCPIP (&open_forwarded_tcpip_command.super.super)

#include "server_tcpforward.c.x"


/* Handling of tcpip-forward */

/* GABA:
   (class
     (name server_forward)
     (super forwarded_port)
     (vars
       (port object resource)))
*/

static struct server_forward *
make_server_forward(struct ssh_connection *connection,
		    const struct address_info *address)
{
  struct io_listen_port *port
    = make_tcpforward_listen_port(connection, ATOM_FORWARDED_TCPIP,
				  address, address);
  if (!port)
    return NULL;

  if (!io_listen(port))
    {
      KILL_RESOURCE(&port->super);
      return NULL;
    }
  else
    {
      NEW(server_forward, self);

      self->super.address = address;
      self->port = &port->super;

      remember_resource(connection->resources, self->port);
      
      return self;      
    }
}

static void
do_tcpip_forward_handler(struct global_request *s UNUSED,
			 struct ssh_connection *connection,
			 const struct request_info *info,
			 struct simple_buffer *args)
{
  uint32_t bind_host_length;
  const uint8_t *bind_host;
  uint32_t bind_port;

  if (parse_string(args, &bind_host_length, &bind_host)
      && parse_uint32(args, &bind_port)
      && parse_eod(args))
    {
      struct address_info *a;
      struct server_forward *forward;

      trace("forward-tcpip request for port %i.\n", bind_port);

      if (bind_port < 1024)
	{
	  werror("Denying forwarding of privileged port %i.\n", bind_port);
	  global_request_reply(connection, info, 0);
	  return;
	}

      if (tcpforward_lookup(&connection->forwarded_ports,
			    bind_host_length, bind_host, bind_port))
	{
	  global_request_reply(connection, info, 0);
	  return;
	}

      a = make_address_info(ssh_format("%ls", bind_host_length, bind_host),
			    bind_port);
      forward = make_server_forward(connection, a);
      
      if (forward)
	{
	  object_queue_add_head(&connection->forwarded_ports,
				&forward->super.super);

	  global_request_reply(connection, info, 1);
	}
      else
	global_request_reply(connection, info, 0);
    }
  else
    {
      werror("Incorrectly formatted tcpip-forward request\n");
      SSH_CONNECTION_ERROR(connection, "Invalid tcpip-forward message.");
    }
}

struct global_request
tcpip_forward_handler =
  { STATIC_HEADER, do_tcpip_forward_handler };

static void
do_tcpip_cancel_forward(struct global_request *s UNUSED,
			struct ssh_connection *connection,
			const struct request_info *info,
			struct simple_buffer *args)
{
  uint32_t bind_host_length;
  const uint8_t *bind_host;
  uint32_t bind_port;

  if (parse_string(args, &bind_host_length, &bind_host) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      CAST(server_forward, forward,
	   tcpforward_remove(&connection->forwarded_ports,
			     bind_host_length,
			     bind_host,
			     bind_port));

      if (forward)
	{
	  assert(forward->port);
	  verbose("Cancelling a requested tcpip-forward.\n");

	  KILL_RESOURCE(forward->port);
	  forward->port = NULL;

	  global_request_reply(connection, info, 1);
	}
      else
	{
	  verbose("Could not find tcpip-forward to cancel\n");

	  global_request_reply(connection, info, 0);
	}
    }
  else
    {
      werror("Incorrectly formatted cancel-tcpip-forward request\n");
      SSH_CONNECTION_ERROR(connection, "Invalid cancel-tcpip-forward message.");
    }
}

struct global_request tcpip_cancel_forward_handler =
{ STATIC_HEADER, do_tcpip_cancel_forward };


/* Handling of direct-tcpip */
     
DEFINE_CHANNEL_OPEN(channel_open_direct_tcpip)
	(struct channel_open *s UNUSED,
	 const struct channel_open_info *info,
	 struct simple_buffer *args)
{
  struct lsh_string *dest_host = NULL;
  uint32_t dest_port;
  const uint8_t *orig_host;
  uint32_t orig_host_length;
  uint32_t orig_port;
  
  if ( (dest_host = parse_string_copy(args))
       && parse_uint32(args, &dest_port) 
       && parse_string(args, &orig_host_length, &orig_host)
       && parse_uint32(args, &orig_port) 
       && parse_eod(args))
    {
      struct resource *r;
      
      verbose("direct-tcpip to %pS:%i.\n", dest_host, dest_port);

      r = tcpforward_connect(make_address_info(dest_host, dest_port),
			     info);
      if (r)
	remember_resource(info->connection->resources, r);
    }
  else
    {
      lsh_string_free(dest_host);
      
      werror("do_channel_open_direct_tcpip: Invalid message!\n");
      SSH_CONNECTION_ERROR(info->connection, "Invalid CHANNEL_OPEN direct-tcpip message.");
    }
}
