/* tcpforward_commands.c
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balazs Scheidler, Niels Möller
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

#include "tcpforward_commands.h"

#define GABA_DEFINE
#include "tcpforward_commands.h.x"
#endif GABA_DEFINE

#include "tcpforward_commands.c.x"


/* Takes a socket as argument, and returns a tcpip channel. Used by
 * the party receiving a open-tcp request, when a channel to the
 * target has been opened. */

static int do_tcpip_connect_io(struct command *ignored UNUSED,
			       struct lsh_object *x,
			       struct command_continuation *c)
{
  CAST(io_fd, socket, x);
  struct ssh_channel *channel;
  
  if (!socket)
    COMMAND_RETURN(c, NULL);

  channel = make_tcpip_channel(socket);

  self->channel->receive = do_tcpip_receive;
  self->channel->send = do_tcpip_send;
  self->channel->eof = do_tcpip_eof;
  
  io_read_write(socket, 
		make_channel_read_data(&self->channel->super), 

		/* FIXME: Make this configurable */
		SSH_MAX_PACKET * 10, /* self->block_size, */
		make_channel_close(&self->channel->super));

  /* Flow control */
  fd->buffer->report = &self->channel->super;

  COMMAND_RETURN(channel);
}

struct command tcpip_start_io = STATIC_COMMAND(do_tcpip_connect_io);

#define TCPIP_START_IO (&tcpip_start_io.super)

/* Used by the party requesting tcp forwarding, i.e. when a socket is
 * already open, and we have asked the other end to forward it. Takes
 * a channel as argument, and connects it to the socket. Returns the
 * channel. */

static struct lsh_object *do_tcpip_start_io(struct command *s UNUSED, 
					    struct lsh_object *x,
					    struct command_continuation *c)
{
  CAST_SUBTYPE(tcpip_channel, channel, x);
  if (!channel)
    {
      verbose("Error opening channel.\n");
      return NULL;
    }

  channel->super.receive = do_tcpip_receive;
  channel->super.send = do_tcpip_send;
  channel->super.eof = do_tcpip_eof;

  /* Install callbacks on the local socket */
  io_read_write(channel->socket,
		make_channel_read_data(&channel->super),
		SSH_MAX_PACKET,
		make_channel_close(&channel->super));

  COMMAND_RETURN(c, x);
}

struct command tcpip_start_io =
{ STATIC_HEADER, do_tcpip_start_io };


/* Requesting the opening of a forwarded tcpip channel. */

/* Used for both forwarded-tcpip and direct-tcpip. Takes a listen
 * value as argument, and returns a channel connected to some tcpip
 * port at the other end. */

/* GABA:
   (class
     (name open_tcpip_command)
     (super channel_open_command)
     (vars
       ; ATOM_FORWARDED_TCPIP or ATOM_DIRECT_TCPIP
       (type . int)
       ; For forwarded-tcpip, port is the port listened to.
       ; For direct-tcpip, poprt is the port to conect to.
       ; In both cases, it's a port used on the server end.
       (port object address_info)
       (peer object listen_value)))
*/

static struct ssh_channel *
new_tcpip_channel(struct channel_open_command *c,
		  struct ssh_connection *connection,
		  struct lsh_string **request)
{
  CAST(open_tcpip_command, self, c);
  struct ssh_channel *channel;

  /* NOTE: All accepted fd:s must end up in this function, so it
   * should be ok to delay the REMEMBER() call until here. */
  
  REMEMBER_RESOURCE(connection->resources, &self->peer->fd->super.super);
  
  channel = make_tcpip_channel(self->peer->fd);
  channel->write = connection->write;

  *request = prepare_channel_open(connection->channels, self->type, 
  				  channel, 
  				  "%S%i%S%i",
				  self->local->ip, self->local->port,
				  self->peer->peer->ip, self->peer->peer->port);
  
  return channel;
}

static struct command *
make_open_tcpip_command(int type,
			struct address_info *local,
			struct listen_value *peer)
{
  NEW(open_forwarded_tcpip_command, self);
  
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_forwarded_tcpip_channel;

  self->type = type;
  self->local = local;
  self->peer = peer;
  
  return &self->super.super;
}

static struct lsh_object *
collect_open_forwarded_tcp(struct collect_info_2 *info,
			   struct lsh_object *a,
			   struct lsh_object *b)
{
  CAST(address_info, local, a);
  CAST(listen_value, peer, b);

  assert(!info);

  return &make_open_forwarded_tcpip_command(ATOM_FORWARDED_TCPIP,
					    local, peer)->super;
}

static struct collect_info_2 collect_open_forwarded_tcp_2 =
STATIC_COLLECT_2_FINAL(collect_open_forwarded_tcp);

struct collect_info_1 open_forwarded_tcp =
STATIC_COLLECT_1(&collect_open_forwarded_tcp_2);

static struct lsh_object *
collect_open_direct_tcp(struct collect_info_2 *info,
			struct lsh_object *a,
			struct lsh_object *b)
{
  CAST(address_info, local, a);
  CAST(listen_value, peer, b);

  assert(!info);

  return &make_open_forwarded_tcpip_command(ATOM_DIRECT_TCPIP,
					    local, peer)->super;
}

static struct collect_info_2 collect_open_direct_tcp_2 =
STATIC_COLLECT_2_FINAL(collect_open_direct_tcp);

struct collect_info_1 open_forwarded_tcp =
STATIC_COLLECT_1(&collect_open_direct_tcp_2);


/* Requesting remote forwarding of a port */

/* GABA:
   (class
     (name remote_port_install_continuation)
     (super command_frame)
     (vars
       (callback object command)))
*/

static int do_remote_port_install_continuation(struct command_continuation *s,
					       struct lsh_object *x)
{
  CAST(remote_port_install_continuation, self, s);
  CAST(remote_port, port, x);
  
  port->callback = self->callback;

  return COMMAND_RETURN(self->super.up, x);
}

static struct command_continuation *
make_remote_port_install_continuation(struct command *callback,
				      struct command_continuation *c)
{
  NEW(remote_port_install_continuation, self);

  self->super.super.c = do_remote_port_install_continuation;
  self->super.up = c;
  self->callback = callback;

  return &self->super.super;
}

/* Listening on a remote port
 *
 * (remote_listen callback port connection)
 *
 * Returns a remote_port or NULL.
 * 
 * callback is invoked with a address_info peer as argument, and
 * should return a channel or NULL.
 */

/* GABA:
   (class
     (name request_tcpip_forward_command)
     (super global_request_command)
     (vars
       ; Invoked when a forwarded_tcpip request is received.
       ; Called with the struct address_info *peer as argument.
       (callback object command)
       (port object address_info))) */

static struct lsh_string *
do_format_request_tcpip_forward(struct global_request_command *s,
				struct ssh_connection *connection,
				struct command_continuation **c)
{
  CAST(request_tcpip_forward_command, self, s);
  struct remote_port *port;
  int want_reply;
  
  if (c)
    {
      port = make_remote_port(self->port, NULL);
      *c = make_remote_port_install_continuation(self->callback, *c);
      want_reply = 1;
    }
  else
    {
      port = make_remote_port(self->port, self->callback);
      want_reply = 0;
    }
  
  object_queue_add_tail(&connection->channels->remote_ports,
			&port->super.super);
  
  return ssh_format("%c%a%c%S%i", SSH_MSG_GLOBAL_REQUEST, ATOM_TCPIP_FORWARD,
		    want_reply, self->port->ip, self->port->port);
}
		    
static struct command *
make_request_tcpip_forward_command(struct command *callback,
				   struct address_info *listen)
{
  NEW(request_tcpip_forward_command, self);
  self->super.super.call = do_channel_global_command;
  self->super.format_request = do_format_request_tcpip_forward;

  self->callback = callback;
  self->port = listen;
  
  return &self->super.super;
}

static struct lsh_object *
collect_remote_listen(struct collect_info_2 *info,
		      struct lsh_object *a, struct lsh_object *b)
{
  CAST_SUBTYPE(command, callback, a);
  CAST(address_info, port, b);
  assert(!info);
  
  return &make_request_tcpip_forward_command(callback, port)->super;
}

static struct collect_info_2 collect_info_remote_listen_2 =
STATIC_COLLECT_2_FINAL(collect_remote_listen);

static struct collect_info_1 remote_listen_command =
STATIC_COLLECT_1(&collect_info_remote_listen_2);


/* Cancel a remotely forwarded port.
 * FIXME: Not implemented */



/* GABA:
   (expr
     (name make_forward_local_port)
     (globals
       (listen LISTEN_COMMAND)
       (start_io FORWARD_START_IO)
       (open_direct_tcp OPEN_DIRECT_TCP))
     (params
       (backend object io_backend)
       (local object address_info)
       (target object address_info))
     (expr
       (lambda (connection)
         (listen (lambda (peer)
	           (start_io (open_direct_tcp target peer connection)))
		 backend
	         local))))
*/

struct command *forward_local_port(struct io_backend *backend,
				   struct address_info *local,
				   struct address_info *target)
{
  CAST(command, res, make_forward_local_port(backend, local, target));

  return res;
}

/* GABA:
   (expr
     (name make_forward_remote_port)
     (globals
       (remote_listen REMOTE_LISTEN)
       ;; (connection_remember CONNECTION_REMEMBER)
       (start_io TCPIP_START_IO))
     (params
       (connect object command)
       (remote object address_info)
       (target object address_info))
     (expr
       (lambda (connection)
         (remote_listen (lambda (peer)
	                  (start_io peer
			            (connect target connection)))
	                remote
			connection))))
*/

struct command *forward_remote_port(struct io_backend *backend,
				    struct address_info *local,
				    struct address_info *target)
{
  CAST_SUBTYPE(command, connect,
       COMMAND_SIMPLE(&connect_with_connection.super, backend));
  CAST_SUBTYPE(command, res,
       make_forward_remote_port(connect, local, target));

  return res;
}

