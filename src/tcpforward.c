/* tcpforward.c
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

#include "tcpforward.h"

#include "channel_commands.h"
#include "format.h"
#include "io_commands.h"
#include "ssh.h"
#include "werror.h"

#if 0
#include "parse.h"
#include "read_data.h"
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>

/* Forward declarations */
extern struct command_simple forward_start_io;
extern struct collect_info_1 open_forwarded_tcp;
extern struct collect_info_1 open_direct_tcp;
extern struct collect_info_1 remote_listen_command;
extern struct collect_info_1 start_forwarded_client_io;

#define FORWARD_START_IO (&forward_start_io.super.super)
#define OPEN_FORWARDED_TCP (&open_forwarded_tcp.super.super.super)
#define OPEN_DIRECT_TCP (&open_direct_tcp.super.super.super)
#define REMOTE_LISTEN (&remote_listen_command.super.super.super)
#define START_FORWARDED_CLIENT_IO (&start_forwarded_client_io.super.super.super)

#define GABA_DEFINE
#include "tcpforward.h.x"
#undef GABA_DEFINE

#include "tcpforward.c.x"

#if 0
static struct fd_callback *
make_tcpip_connected(struct tcpip_channel *c,
		     struct channel_open_callback *response,
		     UINT32 block_size);
#endif

/* GABA:
   (class
     (name local_port)
     (super forwarded_port)
     (vars
       (socket object lsh_fd)))
*/
       
static struct local_port *
make_local_port(struct address_info *address, struct lsh_fd *socket)
{
  NEW(local_port, self);

  self->super.listen = address;  
  self->socket = socket;
  return self;
}
  
static struct forwarded_port *
lookup_forward(struct object_queue *q,
	       UINT32 length, UINT8 *ip, UINT32 port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST(forwarded_port, f, n);
      
      if ( (port == f->listen->port)
	   && (lsh_string_cmp_l(f->listen->ip, length, ip) == 0) )
	return f;
    }
  return NULL;
}

static struct local_port *
remove_forward(struct object_queue *q, int null_ok,
	       UINT32 length, UINT8 *ip, UINT32 port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST(local_port, f, n);
      
      if ( (port == f->super.listen->port)
	   && (lsh_string_cmp_l(f->super.listen->ip, length, ip) == 0) )
	{
	  if (null_ok || f->socket)
	    {
	      FOR_OBJECT_QUEUE_REMOVE(q, n);
	      return f;
	    }
	  else return NULL;
	}
    }
  return NULL;
}

/* TCP forwarding channel */
/* GABA:
   (class
     (name tcpip_channel)
     (super ssh_channel)
     (vars
       (socket object io_fd)))
*/

static int do_tcpip_receive(struct ssh_channel *c,
			    int type, struct lsh_string *data)
{
  CAST(tcpip_channel, closure, c);
  
  switch (type)
    {
    case CHANNEL_DATA:
      return A_WRITE(&closure->socket->buffer->super, data);
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      return LSH_OK | LSH_GOON;
    default:
      fatal("Internal error. do_tcpip_receive()");
    }
}

static int do_tcpip_send(struct ssh_channel *c)
{
  CAST(tcpip_channel, closure, c);
  
  closure->socket->super.want_read = 1;
  
  return LSH_OK | LSH_GOON;
}

static int do_tcpip_eof(struct ssh_channel *c)
{
  if ( (c->flags & CHANNEL_SENT_EOF)
       && (c->flags & CHANNEL_CLOSE_AT_EOF))
    return channel_close(c);
  else
    return LSH_OK | LSH_GOON;
}
                      
static struct tcpip_channel *make_tcpip_channel(struct io_fd *socket)
{
  NEW(tcpip_channel, self);
  
  init_channel(&self->super);
  self->socket = socket;

  if (socket)
    socket->buffer->report = &self->super.super;
  
  return self;
}

/* GABA:
   (class
     (name direct_tcp_server_start_io)
     (super command)
     (vars
       (block_size . UINT32)
       (response object channel_open_callback)
       (channel object tcpip_channel)))
*/
  
static int do_direct_tcp_server_start_io(struct command *s, 
					 struct lsh_object *x, 
					 struct command_continuation *c)
{
  CAST(direct_tcp_server_start_io, self, s);
  CAST_SUBTYPE(io_fd, fd, x);
  int res;

  if (!fd)
    {
      verbose("Forward-request, error establishing connection.\n");
      return CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
  				   SSH_OPEN_CONNECT_FAILED, STRERROR(errno), NULL);
    }

  self->channel->super.receive = do_tcpip_receive;
  self->channel->super.send = do_tcpip_send;
  self->channel->super.eof = do_tcpip_eof;
  
  self->channel->socket = 
     io_read_write(fd, 
		   make_channel_read_data(&self->channel->super), 
		   self->block_size,
		   make_channel_close(&self->channel->super));
  /* Flow control */
  fd->buffer->report = &self->channel->super.super;
  
  res = COMMAND_RETURN(c, (struct lsh_object *) self->channel);
  
  return res | (LSH_CLOSEDP(res)
		? CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
					SSH_OPEN_RESOURCE_SHORTAGE, "Error creating channel.", NULL)
		: CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
					0, NULL, NULL));
}

static struct command *
make_direct_tcp_server_start_io(struct channel_open_callback *response, 
			     struct tcpip_channel *channel,
			     UINT32 block_size)
{
  NEW(direct_tcp_server_start_io, self);

  self->super.call = do_direct_tcp_server_start_io;

  self->response = response;
  self->block_size = block_size;
  self->channel = channel;
  return &self->super;
}

/* GABA:
   (expr
     (name make_direct_tcp_connect)
     (params
       (connect object command)
       (start_io object command))
     (expr
       (lambda (port) (start_io (connect port)))))
*/
  
/* GABA:
   (class
     (name channel_open_direct_tcpip)
     (super channel_open)
     (vars
       (backend object io_backend)))
*/

static int do_channel_open_direct_tcpip(struct channel_open *c,
					struct ssh_connection *connection,
					struct simple_buffer *args,
					struct channel_open_callback *response)
{
  CAST(channel_open_direct_tcpip, closure, c);

  struct lsh_string *dest_host;
  UINT32 dest_port;
  UINT8 *orig_host;
  UINT32 orig_host_length;
  UINT32 orig_port;
  
  if ( (dest_host = parse_string_copy(args))
       && parse_uint32(args, &dest_port) 
       && parse_string(args, &orig_host_length, &orig_host)
       && parse_uint32(args, &orig_port) 
       && parse_eod(args))
    {
      struct address_info *a; 
      int res;

      /* FIXME: It might be more elegant to create this object only
       * once. I.e. have some command that is invoked when the
       * ssh-connection service is created, which installs a handler
       * for direct-tcp, and also creates a function which can be
       * invoked with a port to connect to appropriate. I'm not sure
       * how to get this right though; perhaps the start_io command
       * should be made a continuation instead. I.e. a connection should be created with
       *
       * COMMAND_CALL(closure->connect_command, port, make_start_io(make_tcpip_channel()))
       */
      struct lsh_object *o = 
	make_direct_tcp_connect(make_simple_connect(closure->backend, 
						    connection->resources),
				make_direct_tcp_server_start_io
				(response,
				 /* FIXME: Is it ok to pass NULL
				  * to make_tcpip_channel() ? */
				 make_tcpip_channel(NULL),
				 SSH_MAX_PACKET));

      verbose("direct-tcp connection attempt\n");
      
      /* FIXME: implement filtering on original host? */
      
      a = make_address_info(dest_host, dest_port);

      {
	CAST_SUBTYPE(command, forward_connect, o);      
	res = COMMAND_CALL(forward_connect, a, NULL);
	if (LSH_CLOSEDP(res))
	  return CHANNEL_OPEN_CALLBACK(response, NULL, 
				       SSH_OPEN_CONNECT_FAILED, 
				       "Error connecting to host", 
 				       NULL);
	return res;
      }
    }
  else
    {
      lsh_string_free(dest_host);
      
      werror("do_channel_open_direct_tcpip: Invalid message!\n");
      return LSH_FAIL | LSH_DIE;
    }
}

struct channel_open *make_channel_open_direct_tcpip(struct io_backend *backend)
{
  NEW(channel_open_direct_tcpip, self);
  
  self->super.handler = do_channel_open_direct_tcpip;
  self->backend = backend;
  return &self->super;
}

/* Start i/o on a forwarded channel. Used by clients requesting
 * direct-tcp, and servers requesting tcp_forward. I.e. by the party
 * that accepted a connection for forwarding. */
static struct lsh_object *do_forward_start_io(struct command_simple *c UNUSED, 
					      struct lsh_object *x)
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

  return x;
}

static struct command_simple forward_start_io = 
STATIC_COMMAND_SIMPLE(do_forward_start_io);

/* GABA:
   (class
     (name open_forwarded_tcpip_command)
     (super channel_open_command)
     (vars
       (local object address_info)
       (peer object listen_value)))
*/

static struct ssh_channel *
new_forwarded_tcpip_channel(struct channel_open_command *c,
			    struct ssh_connection *connection,
			    struct lsh_string **request)
{
  CAST(open_forwarded_tcpip_command, self, c);
  struct tcpip_channel *channel;

  /* NOTE: All accepted fd:s must end up in this function, so it
   * should be ok to delay the REMEMBER() call until here. */
  
  REMEMBER_RESOURCE(connection->resources, &self->peer->fd->super.super);
  
  channel = make_tcpip_channel(self->peer->fd);
  channel->super.write = connection->write;

  *request = prepare_channel_open(connection->channels, ATOM_FORWARDED_TCPIP, 
  				  &channel->super, 
  				  "%S%i%S%i",
				  self->local->ip, self->local->port,
				  self->peer->peer->ip, self->peer->peer->port);
  
  return &channel->super;
}

static struct command *
make_open_forwarded_tcpip_command(struct address_info *local,
				  struct listen_value *peer)
{
  NEW(open_forwarded_tcpip_command, self);
  
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_forwarded_tcpip_channel;

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

  return &make_open_forwarded_tcpip_command(local, peer)->super;
}

static struct collect_info_2 collect_open_forwarded_tcp_2 =
STATIC_COLLECT_2_FINAL(collect_open_forwarded_tcp);

static struct collect_info_1 open_forwarded_tcp =
STATIC_COLLECT_1(&collect_open_forwarded_tcp_2);


/* GABA:
   (expr
     (name make_forward_listen)
     (globals
       (start_io FORWARD_START_IO)
       (open_forwarded_tcp OPEN_FORWARDED_TCP)
       (listen LISTEN_COMMAND))
     (params
       (backend object io_backend)
       (connection object ssh_connection))
     (expr (lambda (port)
       (listen (lambda (peer)
                 (start_io (open_forwarded_tcp port peer connection)))
	       backend port))))
*/

/* GABA:
   (class
     (name tcp_forward_continuation)
     (super command_continuation)
     (vars
       (connection object ssh_connection)
       (forward object local_port)
       (c object global_request_callback)))
*/

static int
do_tcp_forward_continuation(struct command_continuation *c,
			    struct lsh_object *x)
{
  CAST(tcp_forward_continuation, self, c);
  CAST_SUBTYPE(lsh_fd, fd, x);

  assert(self->forward);
  
  if (!fd)
    {
      struct local_port *port
	= remove_forward(&self->connection->channels->local_ports,
			 1,
			 self->forward->super.listen->ip->length,
			 self->forward->super.listen->ip->data,
			 self->forward->super.listen->port);
      assert(port);
      assert(port == self->forward);
      
      return GLOBAL_REQUEST_CALLBACK(self->c, 0);
    }
  
  REMEMBER_RESOURCE(self->connection->resources, &fd->super);

  self->forward->socket = fd;

  return GLOBAL_REQUEST_CALLBACK(self->c, 1);
}

static struct command_continuation *
make_tcpforward_continuation(struct ssh_connection *connection,
			      struct local_port *forward,
			      struct global_request_callback *c)
{
  NEW(tcp_forward_continuation, self);

  self->connection = connection;
  self->forward = forward;
  self->c = c;
  
  self->super.c = do_tcp_forward_continuation;

  return &self->super;
}
  
/* GABA:
   (class
     (name tcpip_forward_request)
     (super global_request)
     (vars
       (backend object io_backend)))
*/

static int do_tcpip_forward_request(struct global_request *s, 
				    struct ssh_connection *connection,
				    struct simple_buffer *args,
				    struct global_request_callback *c)
{
  CAST(tcpip_forward_request, self, s);
  struct lsh_string *bind_host;
  UINT32 bind_port;
  
  if ((bind_host = parse_string_copy(args)) 
      && parse_uint32(args, &bind_port) 
      && parse_eod(args))
    {
      struct address_info *a = make_address_info(bind_host, bind_port);
      struct local_port *forward;

      if (bind_port < 1024)
	{
	  werror("Denying forwarding of privileged port %i.\n", bind_port);
	  return GLOBAL_REQUEST_CALLBACK(c, 0);
	}

      if (lookup_forward(&connection->channels->local_ports,
			 bind_host->length, bind_host->data, bind_port))
	{
	  verbose("An already requested tcp-forward requested again\n");
	  return GLOBAL_REQUEST_CALLBACK(c, 0);
	}
      
      verbose("Adding forward-tcpip\n");
      forward = make_local_port(a, NULL);
      object_queue_add_head(&connection->channels->local_ports,
			    &forward->super.super);

      {
	struct lsh_object *o = make_forward_listen(self->backend, connection);
	
	CAST_SUBTYPE(command, listen, o);
      
	return COMMAND_CALL(listen,
			    a,
			    make_tcpforward_continuation(connection, forward, c));
      }
    }
  else
    {
      werror("Incorrectly formatted tcpip-forward request\n");
      return LSH_FAIL | LSH_CLOSE;
    }
}

struct global_request *make_tcpip_forward_request(struct io_backend *backend)
{
  NEW(tcpip_forward_request, self);
  
  self->super.handler = do_tcpip_forward_request;
  self->backend = backend;
  
  return &self->super;
}

static int do_cancel_tcpip_forward(struct global_request *s UNUSED, 
				   struct ssh_connection *connection,
				   struct simple_buffer *args,
				   struct global_request_callback *c)
{
  UINT32 bind_host_length;
  UINT8 *bind_host;
  UINT32 bind_port;
  
  if (parse_string(args, &bind_host_length, &bind_host) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      struct local_port *port
	= remove_forward(&connection->channels->local_ports, 0,
			 bind_host_length,
			 bind_host,
			 bind_port);

      if (port)
        {
	  assert(port->socket);
	  verbose("Cancelling a requested tcpip-forward.\n");

	  close_fd(port->socket, 0);
	  port->socket = NULL;

	  return GLOBAL_REQUEST_CALLBACK(c, 1);
	}
      else
	{      
	  verbose("Could not find tcpip-forward to cancel\n");

	  return GLOBAL_REQUEST_CALLBACK(c, 0);
	}
    }
  else
    {
      werror("Incorrectly formatted cancel-tcpip-forward request\n");
      return LSH_FAIL | LSH_CLOSE;
    }
}

struct global_request *make_cancel_tcpip_forward_request(void)
{
  NEW(global_request, self);
  
  self->handler = do_cancel_tcpip_forward;
  return self;
}

/* The client side of direct-tcp.
 *
 * FIXME: It's very similar to open_forwarded_tcp_command, perhaps
 * they could be unified? */

/* GABA:
   (class
     (name open_direct_tcpip_command)
     (super channel_open_command)
     (vars
       (target object address_info)
       (peer object listen_value)))
*/

static struct ssh_channel *
new_direct_tcpip_channel(struct channel_open_command *c,
			 struct ssh_connection *connection,
			 struct lsh_string **request)
{
  CAST(open_direct_tcpip_command, self, c);
  struct tcpip_channel *channel;

  /* NOTE: All accepted fd:s must end up in this function, so it
   * should be ok to delay the REMEMBER() call until here. */
  
  REMEMBER_RESOURCE(connection->resources, &self->peer->fd->super.super);
  
  channel = make_tcpip_channel(self->peer->fd);
  channel->super.write = connection->write;

  *request = prepare_channel_open(connection->channels, ATOM_DIRECT_TCPIP, 
  				  &channel->super, 
  				  "%S%i%S%i",
				  self->target->ip, self->target->port,
				  self->peer->peer->ip, self->peer->peer->port);
  
  return &channel->super;
}

static struct command *
make_open_direct_tcpip_command(struct address_info *target,
			       struct listen_value *peer)
{
  NEW(open_direct_tcpip_command, self);
  
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_direct_tcpip_channel;

  self->target = target;
  self->peer = peer;
  
  return &self->super.super;
}

static struct lsh_object *
collect_open_direct_tcp(struct collect_info_2 *info,
			struct lsh_object *a,
			struct lsh_object *b)
{
  CAST(address_info, target, a);
  CAST(listen_value, peer, b);

  assert(!info);

  return &make_open_direct_tcpip_command(target, peer)->super;
}

static struct collect_info_2 collect_open_direct_tcp_2 =
STATIC_COLLECT_2_FINAL(collect_open_direct_tcp);

static struct collect_info_1 open_direct_tcp =
STATIC_COLLECT_1(&collect_open_direct_tcp_2);

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

/* Remote forwarding */

/* Used by the client to keep track of remotely forwarded ports */
/* GABA:
   (class
     (name remote_port)
     (super forwarded_port)
     (vars
       ; Invoked with the peer address_info as argument 
       (c object command_continuation)
       ; Invoked when a forwarded_tcpip request is received.
       ; Called with the struct address_info *peer as argument.
       (callback object command)))
*/

static struct remote_port *
make_remote_port(struct address_info *listen,
		 struct command *callback)
		 
{
  NEW(remote_port, self);

  self->super.listen = listen;  
  self->callback = callback;

  return self;
}

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
  
/* GABA:
   (class
     (name request_tcpip_forward_command)
     (super global_request_command)
     (vars
       ; Invoked when a forwarded_tcpip request is received.
       ; Called with the struct address_info *peer as argument.
       (callback object command)
       (port object address_info)))
*/

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


/* GABA:
   (class
     (name remote_listen_value)
     (vars
       (c object channel_open_callback)
       (peer object address_info)))
*/

static struct remote_listen_value *
make_remote_listen_value(struct channel_open_callback *c,
			 struct address_info *peer)
{
  NEW(remote_listen_value, res);
  res->c = c;
  res->peer = peer;

  return res;
}

#if 0
static int do_remote_listen_value_peer(struct command_simple *ignored UNUSED,
				       struct lsh_object *x)
{
  CAST(remote_listen_value, value, x);
  return &value->peer->super;
}

struct command_simple remote_listen_value_peer =
STATIC_COMMAND_SIMPLE(do_remote_listen_value_peer);
#endif

/* GABA:
   (class
     (name channel_open_forwarded_tcpip)
     (super channel_open_command)
     (vars ))
*/

static int do_channel_open_forwarded_tcpip(struct channel_open *c UNUSED,
					   struct ssh_connection *connection,
					   struct simple_buffer *args,
					   struct channel_open_callback *response)
{
#if 0
  CAST(channel_open_forwarded_tcpip, closure, c); 
#endif  
  UINT32 listen_ip_length;
  UINT8 *listen_ip;
  UINT32 listen_port;
  struct lsh_string *peer_host = NULL;
  UINT32 peer_port;

  if (parse_string(args, &listen_ip_length, &listen_ip)
      && parse_uint32(args, &listen_port)
      && (peer_host = parse_string_copy(args))
      && parse_uint32(args, &peer_port)
      && parse_eod(args))
    {
      CAST(remote_port, port,
	   lookup_forward(&connection->channels->remote_ports,
			  listen_ip_length, listen_ip, listen_port));
	   
      if (port && port->callback)
	/* FIXME: Perhaps it is better to pass a continuation that encapsulates the
	 * response callback? */
	return
	  COMMAND_CALL(port->callback,
		       make_remote_listen_value(response,
						make_address_info(peer_host, peer_port)),
		       NULL);
      
      werror("Received a forwarded-tcpip request on a port for which we\n"
	     "haven't requested forwarding. Denying.\n");

      lsh_string_free(peer_host);
      return CHANNEL_OPEN_CALLBACK(response,
				   NULL, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
				   "Unexpected tcpip-forwarded request", NULL);
    }
  else
    {
      werror("do_channel_open_forwarded_tcpip: Invalid message!\n");

      lsh_string_free(peer_host);
      return LSH_FAIL | LSH_DIE;
    }
}

struct channel_open channel_open_forwarded_tcpip =
{ STATIC_HEADER, do_channel_open_forwarded_tcpip};
						       
/* GABA:
   (class
     (name start_forwarded_client_io)
     (super command)
     (vars
       (c object channel_open_callback)))
*/

/* Copies some code from do_forward_start_io */
static int do_start_forwarded_client_io(struct command *s,
					struct lsh_object *x,
					struct command_continuation *c)
{
  CAST(start_forwarded_client_io, self, s);
  CAST(io_fd, socket, x);
  int res;
  
  struct tcpip_channel *channel;
  
  if (!socket)
    return CHANNEL_OPEN_CALLBACK(self->c, NULL, SSH_OPEN_CONNECT_FAILED,
				 "Connection failed", NULL);

  REMEMBER_RESOURCE(self->c->connection->resources,
		    &socket->super.super);
  
  channel = make_tcpip_channel(socket);

  /* FIXME: Move this stuff to the continuation, and just return the tcpip-channel instead.
   * Where should we do the rememembering of the socket? */
  /* Install callbacks on the local socket */
  io_read_write(socket,
		make_channel_read_data(&channel->super),
		SSH_MAX_PACKET,
		make_channel_close(&channel->super));

  res = CHANNEL_OPEN_CALLBACK(self->c, &channel->super, 0, NULL, NULL);

  if (LSH_CLOSEDP(res))
    return res;

  return res | COMMAND_RETURN(c, channel);
}

static struct command *
make_start_forwarded_client_io(struct channel_open_callback *c)
{
  NEW(start_forwarded_client_io, self);

  self->super.call = do_start_forwarded_client_io;
  self->c = c;

  return &self->super;
}

static struct lsh_object *
collect_start_forwarded_client_io(struct collect_info_1 *info,
				  struct lsh_object *x)
{
  CAST(remote_listen_value, peer, x);
  assert(!info);

  return &make_start_forwarded_client_io(peer->c)->super;
}

static struct collect_info_1 start_forwarded_client_io =
STATIC_COLLECT_1_FINAL(collect_start_forwarded_client_io);

/* GABA:
   (expr
     (name make_forward_remote_port)
     (globals
       (remote_listen REMOTE_LISTEN)
       (start_io START_FORWARDED_CLIENT_IO))
     (params
       (connect object command)
       (remote object address_info)
       (target object address_info))
     (expr
       (lambda (connection)
         (remote_listen (lambda (peer) (start_io peer (connect target)))
	                remote
			connection))))
*/

struct command *forward_remote_port(struct io_backend *backend,
				    struct address_info *local,
				    struct address_info *target)
{
  CAST(command, res,
       make_forward_remote_port(make_simple_connect(backend, NULL),
				local, target));

  return res;
}
