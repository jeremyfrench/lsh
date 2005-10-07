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
#include "io_commands.h"
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
       ; port == NULL means that we are setting up a forward for this
       ; port, but are not done yet.
       (port object resource)))
*/

static struct server_forward *
make_server_forward(struct address_info *address, struct resource *port)
{
  NEW(server_forward, self);

  self->super.address = address;
  self->port = port;
  return self;
}

static struct server_forward *
remove_server_forward(struct object_queue *q,
		      uint32_t length, const uint8_t *ip, uint32_t port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST(server_forward, f, n);

      if ( (port == f->super.address->port)
	   && lsh_string_eq_l(f->super.address->ip, length, ip) )
	{
	  if (!f->port)
	    break;

	  FOR_OBJECT_QUEUE_REMOVE(q, n);
	  return f;
	}
    }
  return NULL;
}


/* FIXME: Some duplication with open_direct_tcpip in client_tcpforward.c. */

/* (open_forwarded_tcpip port connection listen_value) */
DEFINE_COMMAND3(open_forwarded_tcpip_command)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct lsh_object *a3,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(address_info, port, a1);
  CAST_SUBTYPE(ssh_connection, connection, a2);
  CAST(listen_value, lv, a3);

  struct channel_forward *channel;

  io_register_fd(lv->fd, "forwarded socket");
  channel = make_channel_forward(lv->fd, TCPIP_WINDOW_SIZE);

  if (!channel_open_new_type(connection, &channel->super, ATOM_FORWARDED_TCPIP,
			     "%S%i%S%i",
			     port->ip, port->port,
			     lv->peer->ip, lv->peer->port))

    {
      EXCEPTION_RAISE(e, make_exception(EXC_CHANNEL_OPEN, SSH_OPEN_RESOURCE_SHORTAGE,
					"Allocating a local channel number failed."));
      KILL_RESOURCE(&channel->super.super);
    }
  else
    {
      assert(!channel->super.channel_open_context);
      channel->super.channel_open_context = make_command_context(c, e);
    }
}

/* GABA:
   (expr
     (name tcpforward_forwarded_tcpip)
     (storage static)
     (params
       (port object address_info))
     (expr
       (lambda (connection)
	 ;; The continuation is responsible for putting the port
	 ;; on the connection's resource list
	 (listen_tcp
	   (lambda (peer)
	     (open_forwarded_tcpip port connection peer))
	   (prog1 port connection)))))
*/

/* GABA:
   (class
     (name tcpip_forward_request_continuation)
     (super command_continuation)
     (vars
       (forward object server_forward)
       (connection object ssh_connection)
       (c object command_continuation)))
*/

static void
do_tcpip_forward_request_continuation(struct command_continuation *c,
				      struct lsh_object *x)
{
  CAST(tcpip_forward_request_continuation, self, c);
  CAST_SUBTYPE(resource, port, x);

  trace("do_tcpip_forward_request_continuation\n");
  assert(self->forward);
  assert(port);
  assert(self->forward->port);

  self->forward->port = port;
  remember_resource(self->connection->resources, port);

  /* FIXME: Is there anything useful we can return? */
  COMMAND_RETURN(self->c, &self->forward->super.super);
}

static struct command_continuation *
make_tcpip_forward_request_continuation(struct server_forward *forward,
					struct ssh_connection *connection,
					struct command_continuation *c)
{
  NEW(tcpip_forward_request_continuation, self);

  trace("make_tcpip_forward_request_continuation\n");
  self->forward = forward;
  self->connection = connection;
  self->c = c;

  self->super.c = do_tcpip_forward_request_continuation;

  return &self->super;
}

/* GABA:
   (class
     (name tcpip_forward_request_exception_handler)
     (super exception_handler)
     (vars
       (connection object ssh_connection)
       (forward object server_forward)
       (parent object exception_handler)))
*/

static void
do_tcpip_forward_request_exc(struct exception_handler *s,
			     const struct exception *e)
{
  CAST(tcpip_forward_request_exception_handler, self, s);

  int res = tcpforward_remove_port(&self->connection->forwarded_ports,
				   &self->forward->super);

  assert(res);

  EXCEPTION_RAISE(self->parent, e);
}

static struct exception_handler *
make_tcpip_forward_request_exc(struct ssh_connection *connection,
			       struct server_forward *forward,
			       struct exception_handler *parent,
			       const char *context)
{
  NEW(tcpip_forward_request_exception_handler, self);
  self->super.raise = do_tcpip_forward_request_exc;
  self->super.context = context;

  self->connection = connection;
  self->forward = forward;
  self->parent = parent;

  return &self->super;
}

static void
do_tcpip_forward_handler(struct global_request *s UNUSED,
			 struct ssh_connection *connection,
			 uint32_t type UNUSED,
			 int want_reply UNUSED,
			 struct simple_buffer *args,
			 struct command_continuation *c,
			 struct exception_handler *e)
{
  struct lsh_string *bind_host;
  uint32_t bind_port;

  if ((bind_host = parse_string_copy(args))
      && parse_uint32(args, &bind_port)
      && parse_eod(args))
    {
      struct address_info *a = make_address_info(bind_host, bind_port);
      struct server_forward *forward;
      struct command *callback;

      trace("forward-tcpip request for port %i.\n", bind_port);

      if (bind_port < 1024)
	{
	  werror("Denying forwarding of privileged port %i.\n", bind_port);
	  EXCEPTION_RAISE(e, make_exception(EXC_GLOBAL_REQUEST, 0,
					    "Denying forward of privileged port."));
	  return;
	}

      if (tcpforward_lookup(&connection->forwarded_ports,
			    STRING_LD(bind_host), bind_port))
	{
	  EXCEPTION_RAISE(e, make_exception(EXC_GLOBAL_REQUEST, 0,
					    "Port already forwarded"));

	  return;
	}

      forward = make_server_forward(a, NULL);
      object_queue_add_head(&connection->forwarded_ports,
			    &forward->super.super);

      callback = tcpforward_forwarded_tcpip(a);

      COMMAND_CALL(callback, connection,
		   make_tcpip_forward_request_continuation(forward,
							   connection,
							   c),
		   make_tcpip_forward_request_exc(connection, forward,
						  e, HANDLER_CONTEXT));

      return;
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
			uint32_t type UNUSED,
			int want_reply UNUSED,
			struct simple_buffer *args,
			struct command_continuation *c,
			struct exception_handler *e)
{
  uint32_t bind_host_length;
  const uint8_t *bind_host;
  uint32_t bind_port;

  if (parse_string(args, &bind_host_length, &bind_host) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      /* FIXME: If tcpforward_forwarded_tcpip doesn't return
	 immediately, and we receive a cancel request before the
	 forwarding is setup (which should be ok, if the forwarding
	 was requested with want_reply == 0), cancelling fails and the
	 client has to try again later. */

      struct server_forward *forward
	= remove_server_forward(&connection->forwarded_ports,
				bind_host_length,
				bind_host,
				bind_port);

      if (forward)
	{
	  assert(forward->port);
	  verbose("Cancelling a requested tcpip-forward.\n");

	  KILL_RESOURCE(forward->port);
	  forward->port = NULL;

	  /* FIXME: What to return? */
	  COMMAND_RETURN(c, connection);
	  return;
	}
      else
	{
	  static const struct exception notfound =
	    STATIC_EXCEPTION(EXC_GLOBAL_REQUEST, 0, "Could not find tcpip-forward to cancel");
	  verbose("Could not find tcpip-forward to cancel\n");

	  EXCEPTION_RAISE(e, &notfound);
	  return;
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
     
static void
do_channel_open_direct_tcpip(struct channel_open *s UNUSED,
			     struct ssh_connection *connection,
			     struct channel_open_info *info UNUSED,
			     struct simple_buffer *args,
			     struct command_continuation *c,
			     struct exception_handler *e)
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
      
      verbose("direct-tcp to %pS:%i.\n", dest_host, dest_port);

      r = tcpforward_connect(make_address_info(dest_host, dest_port),
			     c, e);
      if (r)
	remember_resource(connection->resources, r);
    }
  else
    {
      lsh_string_free(dest_host);
      
      werror("do_channel_open_direct_tcpip: Invalid message!\n");
      SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_OPEN direct-tcp message.");
    }
}

struct channel_open
channel_open_direct_tcpip =
{ STATIC_HEADER, do_channel_open_direct_tcpip };
