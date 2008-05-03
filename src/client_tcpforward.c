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
#include "io_commands.h"
#include "ssh.h"
#include "werror.h"

/* Forward declarations */
/* FIXME: Should be static */
struct command_3 open_direct_tcpip_command;
#define OPEN_DIRECT_TCPIP (&open_direct_tcpip_command.super.super)

#include "client_tcpforward.c.x"


/* Local forwarding using direct-tcpip */

/* (open_direct_tcpip target connection listen_value) */
DEFINE_COMMAND3(open_direct_tcpip_command)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct lsh_object *a3,
      struct command_continuation *c UNUSED,
      struct exception_handler *e)
{
  CAST(address_info, target, a1);
  CAST_SUBTYPE(ssh_connection, connection, a2);
  CAST(listen_value, lv, a3);

  struct channel_forward *channel;

  trace("open_direct_tcpip_command\n");

  io_register_fd(lv->fd, "forwarded socket");
  channel = make_channel_forward(lv->fd, TCPIP_WINDOW_SIZE);
  
  if (!channel_open_new_type(connection, &channel->super,
			     ATOM_LD(ATOM_DIRECT_TCPIP),
			     "%S%i%S%i",
			     target->ip, target->port,
			     lv->peer->ip, lv->peer->port))
			     
    {
      EXCEPTION_RAISE(e, make_exception(EXC_CHANNEL_OPEN, SSH_OPEN_RESOURCE_SHORTAGE,
					"Allocating a local channel number failed."));
      KILL_RESOURCE(&channel->super.super);
    }
}

/* GABA:
   (expr
     (name forward_local_port)
     (params
       (local object address_info)
       (target object address_info))
     (expr
       (lambda (connection)
         (connection_remember connection
           (listen_tcp
	     (lambda (peer)
	       (open_direct_tcpip target connection peer))
	       
	     ; NOTE: The use of prog1 is needed to delay the
	     ; listen_tcp call until the (otherwise ignored)
	     ; connection argument is available.
	     (prog1 local connection))))))
*/

/* Remote forwarding, using tcpip-forward and forwarded-tcpip. */

/* Used by the client to keep track of remotely forwarded ports */
/* GABA:
   (class
     (name remote_port)
     (super forwarded_port)
     (vars
       (active . int)
       (target object address_info)))
*/

static struct remote_port *
make_remote_port(struct address_info *listen,
		 struct address_info *target)
{
  NEW(remote_port, self);

  self->super.address = listen;
  self->active = 0;
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
      CAST(remote_port, port,
	   tcpforward_lookup(&info->connection->forwarded_ports,
			     listen_ip_length, listen_ip, listen_port));
	   
      if (port && port->active)
	{
	  struct resource *r;

	  verbose("forwarded-tcpip for %ps:%i, from %ps:%i.\n",
		  listen_ip_length, listen_ip, listen_port, peer_ip_length, peer_ip, peer_port);
	  
	  r = tcpforward_connect(port->target, info);
	  if (r)
	    remember_resource(info->connection->resources, r);
	}
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
     (name remote_port_continuation)
     (super command_continuation)
     (vars
       (up object command_continuation)
       (port object remote_port)))
*/

static void
do_remote_port_continuation(struct command_continuation *s,
			    struct lsh_object *x)
{
  CAST(remote_port_continuation, self, s);
  CAST_SUBTYPE(ssh_connection, connection, x);

  assert(connection);

  debug("tcpforward_commands.c: do_remote_port_continuation.\n");
  self->port->active = 1;

  COMMAND_RETURN(self->up, x);
}

static struct command_continuation *
make_remote_port_continuation(struct remote_port *port,
			      struct command_continuation *c)
{
  NEW(remote_port_continuation, self);

  debug("tcpforward_commands.c: make_remote_port_continuation\n");

  self->super.c = do_remote_port_continuation;
  self->up = c;

  self->port = port;

  return &self->super;
}

/* GABA:
   (class
     (name remote_port_exception_handler)
     (super exception_handler)
     (vars
       (e object exception_handler)
       (connection object ssh_connection)
       (port object remote_port)))
*/

static void
do_remote_port_exception_handler(struct exception_handler *s,
				 const struct exception *x)
{
  CAST(remote_port_exception_handler, self, s);
  
  tcpforward_remove_port(&self->connection->forwarded_ports,
			 &self->port->super);

  EXCEPTION_RAISE(self->e, x);
}

static struct exception_handler *
make_remote_port_exception_handler(struct ssh_connection *connection,
				   struct remote_port *port,
				   struct exception_handler *e)
{
  NEW(remote_port_exception_handler, self);
  self->super.raise = do_remote_port_exception_handler;
  self->e = e;
  self->connection = connection;
  self->port = port;

  return &self->super;
}
    
/* GABA:
   (class
     (name request_tcpip_forward_command)
     (super command)
     (vars
       ; Remote port to listen on
       (port object address_info)
       ; Target for forwarded connections
       (target object address_info)))
*/

static void
do_request_tcpip_forward(struct command *s,
			 struct lsh_object *x,
			 struct command_continuation *c,
			 struct exception_handler *e)
{
  CAST(request_tcpip_forward_command, self, s);
  CAST_SUBTYPE(ssh_connection, connection, x);
  struct remote_port *port;
  struct command_context *ctx;

  debug("client_tcpforward.c: do_request_tcpip_forward\n");

  port = make_remote_port(self->port, self->target);
  ctx = make_command_context(
    make_remote_port_continuation(port, c),
    make_remote_port_exception_handler(connection, port, e));

  object_queue_add_tail(&connection->forwarded_ports, &port->super.super);

  channel_send_global_request(connection, ATOM_TCPIP_FORWARD, ctx,
			      "%S%i", self->port->ip, self->port->port);
}

struct command *
forward_remote_port(struct address_info *port,
		    struct address_info *target)
{
  NEW(request_tcpip_forward_command, self);
  self->super.call = do_request_tcpip_forward;
  self->port = port;
  self->target = target;

  return &self->super;
}
