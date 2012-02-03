/* client_tcpforward.c
 *
 * Client side of tcpip forwarding.
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
#include "client.h"
#include "io.h"
#include "ssh.h"
#include "werror.h"

#include "client_tcpforward.c.x"


/* FIXME: Use one function to create the port object (called by the
   options parsing in lsh.c), and another function to activate the
   forwarding, called when the connection is ready. */

/* GABA:
   (class
     (name forward_local_port_action)
     (super client_connection_action)
     (vars
       (local const object address_info)
       (target const object address_info)))       
*/

static void
do_forward_local_port(struct client_connection_action *s,
		      struct ssh_connection *connection)
{
  CAST(forward_local_port_action, self, s);
  struct resource *port;

  port = tcpforward_listen(connection, ATOM_DIRECT_TCPIP,
			   self->local, self->target);
  if (port)
    remember_resource(connection->resources, port);

  else
    werror("Could not forward local port %S:%i.\n",
	   self->local->ip, self->local->port);
}

struct client_connection_action *
forward_local_port(const struct address_info *local,
		   const struct address_info *target)
{
  NEW(forward_local_port_action, self);
  self->super.action = do_forward_local_port;
  self->local = local;
  self->target = target;

  return &self->super;
}

/* Remote forwarding, using tcpip-forward and forwarded-tcpip. */

/* Used by the client to keep track of remotely forwarded ports */
/* GABA:
   (class
     (name remote_port)
     (super client_tcpforward_handler)
     (vars
       (target const object address_info)))
*/

static void
do_remote_port_open(struct client_tcpforward_handler *s,
		    const struct channel_open_info *info,
		    uint32_t peer_ip_length, const uint8_t *peer_ip,
		    uint32_t peer_port)
{
  CAST(remote_port, self, s);
  struct resource *r;

  verbose("forwarded-tcpip for %pS:%i, from %ps:%i.\n",
	  self->super.super.address->ip, self->super.super.address->port,
	  peer_ip_length, peer_ip, peer_port);

  r = tcpforward_connect(self->target, info);
  if (r)
    remember_resource(info->connection->resources, r);  
}

    
static struct remote_port *
make_remote_port(const struct address_info *listen,
		 const struct address_info *target)
{
  NEW(remote_port, self);

  self->super.super.address = listen;
  self->super.active = 0;
  self->super.open = do_remote_port_open;
  self->target = target;

  return self;
}

DEFINE_CHANNEL_OPEN(channel_open_forwarded_tcpip)
	(struct channel_open *s UNUSED,
	 const struct channel_open_info *info,
	 struct simple_buffer *args)
{
  uint32_t listen_ip_length;
  const uint8_t *listen_ip;
  uint32_t listen_port;

  uint32_t peer_ip_length;
  const uint8_t *peer_ip;
  uint32_t peer_port;
  
  if (parse_string(args, &listen_ip_length, &listen_ip)
      && parse_uint32(args, &listen_port)
      && parse_string(args, &peer_ip_length, &peer_ip)
      && parse_uint32(args, &peer_port)
      && parse_eod(args))
    {
      CAST_SUBTYPE(client_tcpforward_handler, port,
		   tcpforward_lookup(&info->connection->forwarded_ports,
				     listen_ip_length, listen_ip, listen_port));
	   
      if (port && port->active)
	port->open(port, info, peer_ip_length, peer_ip, peer_port);
      else
	{
	  werror("Received a forwarded-tcpip request on a port for which we\n"
		 "haven't requested forwarding. Denying.\n");

	  channel_open_deny(info,
			    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
			    "Unexpected tcpip-forward request");
	}
    }
  else
    {
      werror("do_channel_open_forwarded_tcpip: Invalid message!\n");

      SSH_CONNECTION_ERROR(info->connection, "Invalid CHANNEL_OPEN forwarded-tcpip message.");
    }
}


/* GABA:
   (class
     (name remote_port_state)
     (super global_request_state)
     (vars       
       (port object remote_port)))
*/

static void
do_remote_port_state_done(struct global_request_state *s,
			  struct ssh_connection *connection,
			  int success)
{
  CAST(remote_port_state, self, s);

  if (success)
    self->port->super.active = 1;
  else
    {
      werror("Forwarding of remote port refused by server.\n");
      tcpforward_remove_port(&connection->forwarded_ports,
			     &self->port->super.super);
    }
}

static struct global_request_state *
make_remote_port_state(struct remote_port *port)
{
  NEW(remote_port_state, self);
  self->super.done = do_remote_port_state_done;
  self->port = port;

  return &self->super;
}


/* GABA:
   (class
     (name request_tcpip_forward_action)
     (super client_connection_action)
     (vars
       ; Remote port to listen on
       (port const object address_info)
       ; Target for forwarded connections
       (target const object address_info)))
*/

static void
do_request_tcpip_forward(struct client_connection_action *s,
			 struct ssh_connection *connection)
{
  CAST(request_tcpip_forward_action, self, s);
  struct remote_port *port;

  debug("client_tcpforward.c: do_request_tcpip_forward\n");

  port = make_remote_port(self->port, self->target);
  object_queue_add_tail(&connection->forwarded_ports, &port->super.super.super);

  channel_send_global_request(connection, ATOM_TCPIP_FORWARD,
			      make_remote_port_state(port),
			      "%S%i", self->port->ip, self->port->port);
}

struct client_connection_action *
forward_remote_port(const struct address_info *port,
		    const struct address_info *target)
{
  NEW(request_tcpip_forward_action, self);
  self->super.action = do_request_tcpip_forward;
  self->port = port;
  self->target = target;

  return &self->super;
}
