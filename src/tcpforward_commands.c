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

#if 0
#define GABA_DEFINE
#include "tcpforward_commands.h.x"
#undef GABA_DEFINE
#endif

#include "atoms.h"
#include "channel_commands.h"
#include "format.h"
#include "io_commands.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* Forward declarations */
/* extern struct command_simple forward_start_io; */
extern struct collect_info_1 open_direct_tcp;
extern struct collect_info_1 remote_listen_command;
extern struct collect_info_1 open_forwarded_tcp;
extern struct command tcpip_start_io;
extern struct command tcpip_connect_io;

struct collect_info_1 install_forwarded_tcp_handler;
static struct command make_direct_tcp_handler;

struct collect_info_1 install_tcpip_forward_request_handler;
static struct command make_forward_tcpip_handler;

/* #define FORWARD_START_IO (&forward_start_io.super.super) */
#define OPEN_DIRECT_TCP (&open_direct_tcp.super.super.super)
#define REMOTE_LISTEN (&remote_listen_command.super.super.super)
#define TCPIP_START_IO (&tcpip_start_io.super)
#define TCPIP_CONNECT_IO (&tcpip_connect_io.super)
#define OPEN_FORWARDED_TCP (&open_forwarded_tcp.super.super.super)


#include "tcpforward_commands.c.x"


/* Takes a socket as argument, and returns a tcpip channel. Used by
 * the party receiving a open-tcp request, when a channel to the
 * target has been opened. */

/* NOTE: This command does not do any remembering. */
static int do_tcpip_connect_io(struct command *ignored UNUSED,
			       struct lsh_object *x,
			       struct command_continuation *c)
{
  CAST(io_fd, socket, x);
  struct ssh_channel *channel;
  
  if (!socket)
    COMMAND_RETURN(c, NULL);

  channel = make_tcpip_channel(socket);
  tcpip_channel_start_io(channel);

  return COMMAND_RETURN(c, channel);
}

struct command tcpip_connect_io = STATIC_COMMAND(do_tcpip_connect_io);

/* Used by the party requesting tcp forwarding, i.e. when a socket is
 * already open, and we have asked the other end to forward it. Takes
 * a channel as argument, and connects it to the socket. Returns the
 * channel. */

static int
do_tcpip_start_io(struct command *s UNUSED, 
		  struct lsh_object *x,
		  struct command_continuation *c)
{
  CAST_SUBTYPE(ssh_channel, channel, x);
  if (!channel)
    {
      verbose("Error opening channel.\n");
      return NULL;
    }

  tcpip_channel_start_io(channel);

  return COMMAND_RETURN(c, channel);
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
				  self->port->ip, self->port->port,
				  self->peer->peer->ip, self->peer->peer->port);
  
  return channel;
}

static struct command *
make_open_tcpip_command(int type,
			struct address_info *port,
			struct listen_value *peer)
{
  NEW(open_tcpip_command, self);
  
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_tcpip_channel;

  self->type = type;
  self->port = port;
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

  return &make_open_tcpip_command(ATOM_FORWARDED_TCPIP,
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

  return &make_open_tcpip_command(ATOM_DIRECT_TCPIP,
				  local, peer)->super;
}

static struct collect_info_2 collect_open_direct_tcp_2 =
STATIC_COLLECT_2_FINAL(collect_open_direct_tcp);

struct collect_info_1 open_direct_tcp =
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
       (start_io TCPIP_START_IO)
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
       (start_io TCPIP_CONNECT_IO))
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

/* Takes a callback function and returns a channel_open
 * handler. */
static int
do_make_direct_tcp_handler(struct command *s UNUSED,
			   struct lsh_object *x,
			   struct command_continuation *c)
{
  CAST_SUBTYPE(command, callback,  x);

  return
    COMMAND_RETURN(c,
		   &make_channel_open_direct_tcpip(callback)->super);
}

static struct command
make_direct_tcp_handler = STATIC_COMMAND(do_make_direct_tcp_handler);

/* Takes a callback function and returns a global_request handler. */
static int
do_make_tcpip_forward_handler(struct command *s UNUSED,
			      struct lsh_object *x,
			      struct command_continuation *c)
{
  CAST_SUBTYPE(command, callback,  x);

  return
    COMMAND_RETURN(c,
		   &make_tcpip_forward_request(callback)->super);
}

static struct command
make_forward_tcpip_handler
= STATIC_COMMAND(do_make_tcpip_forward_handler);


/* Commands to install open hadnlers */
struct install_info install_direct_tcp_info_2 =
STATIC_INSTALL_OPEN_HANDLER(ATOM_DIRECT_TCPIP);

struct collect_info_1 install_direct_tcp_handler =
STATIC_COLLECT_1(&install_direct_tcp_info_2.super);

struct install_info install_forwarded_tcp_info_2 =
STATIC_INSTALL_OPEN_HANDLER(ATOM_FORWARDED_TCPIP);

struct collect_info_1 install_forwarded_tcp_handler =
STATIC_COLLECT_1(&install_forwarded_tcp_info_2.super);

/* Server side callbacks */

/* Make this non-static? */
/* GABA:
   (expr
     (name direct_tcpip_hook)
     (globals
       (install "&install_forwarded_tcp_handler.super.super.super")
       (handler "&make_direct_tcp_handler.super")
       (start_io TCPIP_START_IO))
     (params
       (connect object command))
     (expr
       (lambda (connection)
         (install connection
	   (handler (lambda (port)
	     (start_io (connect connection port))))))))
*/

struct command *
make_direct_tcpip_hook(struct io_backend *backend)
{
  CAST_SUBTYPE(command, res,
	       direct_tcpip_hook(make_connect_connection(backend)));

  return res;
}


/* ;; GABA:
   (expr
     (name forwarded_tcpip_hook)
     (expr
       (lambda (connection)
         ())))
*/

struct install_info install_tcpip_forward_request_info_2 =
STATIC_INSTALL_OPEN_HANDLER(ATOM_TCPIP_FORWARD);

struct collect_info_1 install_tcpip_forward_request_handler =
STATIC_COLLECT_1(&install_tcpip_forward_request_info_2.super);

/* GABA:
   (expr
     (name make_tcpip_forward_hook)
     (globals
       (install "&install_tcpip_forward_request_handler.super.super.super")
       (handler "&make_forward_tcpip_handler.super")
       (start_io TCPIP_START_IO)
       (open_forwarded_tcp OPEN_FORWARDED_TCP)
       (listen LISTEN_COMMAND))
     (params
       (backend object io_backend))
     (expr
       (lambda (connection)
         (install connection
	   (handler (lambda (port)
             (listen (lambda (peer)
                       (start_io (open_forwarded_tcp port peer
		                                     connection)))
	             backend port)))))))
*/

struct command *
tcpip_forward_hook(struct io_backend *backend)
{
  CAST_SUBTYPE(command, res, make_tcpip_forward_hook(backend));

  return res;
}
	 
/* Invoked when a direct-tcp request is received */
/* ;; GABA:
   (expr
     (name forward_connect)
     (globals
       (start_io TCPIP_START_IO))
     (params
       (connect object command))
     (expr
       (lambda (connection port)
         (start_io (connect connection port)))))
*/
