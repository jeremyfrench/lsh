/* gateway_tcpforward.c
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

#include "format.h"
#include "lsh_string.h"
#include "ssh.h"

#include "gateway_tcpforward.c.x"

/* GABA:
   (class
     (name gateway_tcpforward_handler)
     (super client_tcpforward_handler)
     (vars
       (gateway object ssh_connection)))
*/

static void
do_gateway_tcpforward_open(struct client_tcpforward_handler *s,
			   const struct channel_open_info *info,
			   uint32_t peer_ip_length,
			   const uint8_t *peer_ip,
			   uint32_t peer_port)
{
  CAST(gateway_tcpforward_handler, self, s);
  int res;

  struct lsh_string *args
    = ssh_format("%S%i%s%i",
		 self->super.super.address->ip,
		 self->super.super.address->port,
		 peer_ip_length, peer_ip, peer_port);
		    
  res = gateway_forward_channel_open(self->gateway,
				     info,
				     STRING_LD(args));
  lsh_string_free(args);
  if (!res)
    channel_open_deny(info,
		      SSH_OPEN_RESOURCE_SHORTAGE,
		      "Too many channels.");
  return;
}

static struct gateway_tcpforward_handler *
make_gateway_tcpforward_handler(struct address_info *listen,
				struct ssh_connection *gateway)
{
  NEW(gateway_tcpforward_handler, self);
  self->super.super.address = listen;
  self->super.active = 0;
  self->super.open = do_gateway_tcpforward_open;

  self->gateway = gateway;

  return self;
}

/* GABA:
   (class
     (name gateway_tcpforward_state)
     (super global_request_state)
     (vars
       (port object gateway_tcpforward_handler)))
*/

static void
do_gateway_tcpforward_state_done(struct global_request_state *s,
				 struct ssh_connection *connection,
				 int success)
{
  CAST(gateway_tcpforward_state, self, s);
  
  if (success)
    self->port->super.active = 1;
  
  else
    {
      werror("Forwarding of remote port refused by server.\n");
      tcpforward_remove_port(&connection->forwarded_ports,
			     &self->port->super.super);
    }
  global_request_reply(self->port->gateway, NULL, success);
}

static struct global_request_state *
make_gateway_tcpforward_state(struct gateway_tcpforward_handler *handler)
{
  NEW(gateway_tcpforward_state, self);
  self->super.done = do_gateway_tcpforward_state_done;
  self->port = handler;

  return &self->super;
}

/* GABA:
   (class
     (name gateway_forward_resource)
     (super resource)
     (vars
       (connection object ssh_connection)
       (port object forwarded_port))))
*/

static void
do_kill_gateway_forward(struct resource *s)
{
  CAST(gateway_forward_resource, self, s);

  trace("do_kill_gateway_forward\n");
  if (self->super.alive)
    {
      self->super.alive = 0;
      channel_send_global_request(self->connection, ATOM_CANCEL_TCPIP_FORWARD,
				  NULL, "%S%i",
				  self->port->address->ip, self->port->address->port);

      tcpforward_remove_port(&self->connection->forwarded_ports,
			     self->port);
    }
}

static struct resource *
make_gateway_forward_resource(struct ssh_connection *connection,
			      struct forwarded_port *port)
{
  NEW(gateway_forward_resource, self);
  init_resource(&self->super, do_kill_gateway_forward);

  self->connection = connection;
  self->port = port;

  return &self->super;
}
				  
  
static void
do_gateway_tcpip_forward_handler(struct global_request *s UNUSED,
				 struct ssh_connection *c,
				 const struct request_info *info,
				 struct simple_buffer *args)
{
  CAST(gateway_connection, connection, c);
  uint32_t bind_host_length;
  const uint8_t *bind_host;
  uint32_t bind_port;

  /* Require want_reply set */
  if (info->want_reply
      && parse_string(args, &bind_host_length, &bind_host)
      && parse_uint32(args, &bind_port)
      && parse_eod(args))
    {
      struct address_info *a;
      struct gateway_tcpforward_handler *handler;

      if (tcpforward_lookup(&connection->super.forwarded_ports,
			    bind_host_length, bind_host, bind_port))
	{
	  global_request_reply(&connection->super, info, 0);
	  return;
	}

      if (tcpforward_lookup(&connection->shared->super.forwarded_ports,
			    bind_host_length, bind_host, bind_port))
	{
	  global_request_reply(&connection->super, info, 0);
	  return;
	}

      a = make_address_info(ssh_format("%ls", bind_host_length, bind_host),
			    bind_port);
      handler = make_gateway_tcpforward_handler(a, &connection->super);

      object_queue_add_tail(&connection->shared->super.forwarded_ports,
			    &handler->super.super.super);
      object_queue_add_tail(&connection->super.forwarded_ports,
			    &handler->super.super.super);
      
      channel_send_global_request(&connection->shared->super, ATOM_TCPIP_FORWARD,
				  make_gateway_tcpforward_state(handler),
				  "%S%i", a->ip, a->port);

      remember_resource(connection->super.resources,
			make_gateway_forward_resource(&connection->shared->super,
						      &handler->super.super));
    }
  else
    {
      werror("Incorrectly formatted tcpip-forward request\n");
      SSH_CONNECTION_ERROR(&connection->super, "Invalid tcpip-forward message.");
    }    
}

struct global_request
gateway_tcpip_forward_handler =
  { STATIC_HEADER, do_gateway_tcpip_forward_handler };

/* Not implemented. The client never sends CANCEL_TCPIP_FORWARD to a
   gateway. */
#if 0
static void
do_gateway_cancel_tcpip_forward_handler(struct global_request *s UNUSED,
					struct ssh_connection *c,
					const struct request_info *info,
					struct simple_buffer *args)
{
  CAST(gateway_connection, connection, c);

  uint32_t bind_host_length;
  const uint8_t *bind_host;
  uint32_t bind_port;

  if (parse_string(args, &bind_host_length, &bind_host) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      CAST(gateway_tcpforward_handler, forward,
	   tcp_forward_remove(&connection->super.forwarded_ports,
			      bind_host_length,
			      bind_host,
			      bind_port));

      if (forward)
	{
	  struct global_request_state state;

	  if (want_reply)
	    state = make_gateway_cancel_tcpforward_state(...);
	  else
	    {
	      state = NULL;
	      tcpforward_remove_port(&connection->shared->super.forwarded_ports,
				     &forward->super);
	    }

	  channel_send_global_request(&connection->shared->super,
				      ATOM_CANCEL_TCPIP_FORWARD,
				      state,
				      "%s%i", bind_host_length, bind_host,
				      bind_port);
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
      SSH_CONNECTION_ERROR(&connection->super, "Invalid cancel-tcpip-forward message.");
    }
}

struct global_request gateway_cancel_tcpip_forward_handler =
{ STATIC_HEADER, do_gateway_cancel_tcpip_forward };
#endif
