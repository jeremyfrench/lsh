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

#include <errno.h>
#include <string.h>

extern struct command_simple forward_client_start_io;

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

static struct forwarded_port *
make_forwarded_port(struct address_info *address)
{
  NEW(forwarded_port, self);

  self->local = address;  

  return self;
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
                      
static struct tcpip_channel *make_tcpip_channel(void)
{
  NEW(tcpip_channel, self);
  
  init_channel(&self->super);
  
  return self;
}

/* Connect callback */
/* ;; GABA:
   (class
     (name tcpip_connected)
     (super fd_callback)
     (vars 
       (channel object tcpip_channel)
       (backend object io_backend)
       (block_size simple UINT32)
       (response object channel_open_callback)))
*/

/* GABA:
   (class
     (name forward_server_start_io)
     (super command)
     (vars
       (block_size . UINT32)
       (response object channel_open_callback)
       (channel object tcpip_channel)))
*/

#if 0
static int do_tcpip_connected(struct fd_callback **c,
                              int fd)
{
  CAST(tcpip_connected, self, *c);
}
#endif
  
static int do_forward_server_io(struct command *s, 
			        struct lsh_object *x, 
			        struct command_continuation *c)
{
  CAST(forward_server_start_io, self, s);
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

  res = COMMAND_RETURN(c, (struct lsh_object *) self->channel);
  
  return res | (LSH_CLOSEDP(res)
		? CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
					SSH_OPEN_RESOURCE_SHORTAGE, "Error creating channel.", NULL)
		: CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
					0, NULL, NULL));
}

#if 0
static struct fd_callback *
make_tcpip_connected(struct tcpip_channel *channel,
		     struct channel_open_callback *response)
{}
#endif

static struct command *
make_forward_server_start_io(struct channel_open_callback *response, 
			     struct tcpip_channel *channel,
			     UINT32 block_size)
{
  NEW(forward_server_start_io, self);

  self->super.call = do_forward_server_io;

  self->response = response;
  self->block_size = block_size;
  self->channel = channel;
  return &self->super;
}

/* GABA:
   (expr
     (name make_forward_connect)
     (params
       (connect object command)
       (start_io object command))
     (expr
       (lambda (port) (start_io (connect port)))))
*/
  
/* GABA:
   (class
     (name open_direct_tcpip)
     (super channel_open)
     (vars
       (backend object io_backend)))
*/

static int do_open_direct_tcpip(struct channel_open *c,
			        struct ssh_connection *connection,
			        struct simple_buffer *args,
			        struct channel_open_callback *response)
{
  CAST(open_direct_tcpip, closure, c);

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
	make_forward_connect(make_simple_connect(closure->backend, 
						 connection->resources),
			     make_forward_server_start_io(response, 
						          make_tcpip_channel(),
							  SSH_MAX_PACKET));
      
      verbose("direct-tcp connection attempt\n");
      
      /* FIXME: implement filtering on original host? */

      a = make_address_info(dest_host, dest_port);

#if 0
      if (tcp_addr(&sin, dest_host_length, dest_host, dest_port))
        {
	  struct tcpip_channel *direct_tcpip = make_tcpip_channel();
          connect = io_connect(closure->backend,
			       &sin, NULL,
			       make_tcpip_connected(direct_tcpip,
						    response,
						    SSH_MAX_PACKET));
          if (!connect)
            {
	      KILL(direct_tcpip);
	      return CHANNEL_OPEN_CALLBACK(response, NULL,
					   SSH_OPEN_CONNECT_FAILED,
					   STRERROR(errno),
					   NULL);
            }
	  REMEMBER_RESOURCE(connection->resources,
			    &connect->super.super);
	  return LSH_OK | LSH_GOON;
        }
      else
	{
	  /* tcp_addr failed */
	  return CHANNEL_OPEN_CALLBACK(response, NULL,
				       SSH_OPEN_CONNECT_FAILED,
				       "No such host",
				       NULL);
	}
#endif
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
      werror("do_open_direct_tcpip: Invalid message!\n");
      return LSH_FAIL | LSH_DIE;
    }
}

struct channel_open *make_open_direct_tcpip(struct io_backend *backend)
{
  NEW(open_direct_tcpip, self);
  
  self->super.handler = do_open_direct_tcpip;
  self->backend = backend;
  return &self->super;
}

static struct lsh_object *do_forward_client_io(struct command_simple *c UNUSED, 
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
  channel->socket = 
  	io_read_write(channel->socket,
  		      make_channel_read_data(&channel->super),
		      SSH_MAX_PACKET,
		      make_channel_close(&channel->super));

  return x;
}

struct command_simple forward_client_start_io = 
STATIC_COMMAND_SIMPLE(do_forward_client_io);

/* GABA:
   (class
     (name open_tcpip_command)
     (super channel_open_command)
     (vars
       (connection object ssh_connection)
       (peer object listen_value)
       (port object forwarded_port)))
*/

static int do_open_tcpip_channel(struct command *s,
				 struct lsh_object *x,
				 struct command_continuation *c)
{
  CAST(open_tcpip_command, self, s);
  if (x) 
    {
      CAST(listen_value, peer, x);
      self->peer = peer;
      /* FIXME: do_channel_open_command is not supposed to be called in this way. */
      return do_channel_open_command(s, (struct lsh_object *) self->connection, c);
    }
  return COMMAND_RETURN(c, NULL);
}

static struct ssh_channel *new_tcpip_channel(struct channel_open_command *c,
					     struct ssh_connection *connection,
					     struct lsh_string **request)
{
  CAST(open_tcpip_command, self, c);
  struct tcpip_channel *channel;
  
  channel = make_tcpip_channel();
  channel->super.write = connection->write;
  channel->socket = self->peer->fd;

  *request = prepare_channel_open(connection->channels, ATOM_FORWARDED_TCPIP, 
  				  &channel->super, 
  				  "%S%i%S%i",
				  self->port->local->ip, self->port->local->port,
				  self->peer->peer->ip, self->peer->peer->port);
  
  return &channel->super;
}

static struct command *make_open_tcpip_command(struct ssh_connection *connection, struct forwarded_port *port)
{
  NEW(open_tcpip_command, self);
  
  self->super.super.call = do_open_tcpip_channel;
  self->super.new_channel = new_tcpip_channel;
  self->connection = connection;
  self->port = port;
  
  return &self->super.super;
}

/* FIXME: Using a channel_open object in this way is not quite right.
 * channel_open-commands are supposed to take an connection as argument.
 *
 * Perhaps one should use something like
 *
 * (lambda (connection port) (start-io (make-direct-tcp-foo (listen port) connection)))
 *
 * instead.
 */
/* GABA:
    (expr
     (name make_forward_listen)
     (globals
       (start_io "&forward_client_start_io.super.super"))
     (params
       (listen object command)
       (channel_open object command))
     (expr
       (lambda (port) (start_io (channel_open (listen port))))))
*/

/* GABA:
   (class
     (name tcpip_forward_request)
     (super global_request)
     (vars
       (backend object io_backend)))
*/

static int do_tcpip_forward_request(struct global_request *c, 
				    struct ssh_connection *connection,
				    int want_reply UNUSED, 
				    struct simple_buffer *args)
{
  CAST(tcpip_forward_request, self, c);
  struct lsh_string *bind_host;
  UINT32 bind_port;
  
  if ((bind_host = parse_string_copy(args)) 
      && parse_uint32(args, &bind_port) 
      && parse_eod(args))
    {
      struct address_info *a = make_address_info(bind_host, bind_port);
      struct forwarded_port *port;
      struct lsh_object *o;
      int res;
      
      FOR_OBJECT_QUEUE(connection->forwarded_ports, n)
        {
          CAST(forwarded_port, f, n);

	  if ( (bind_port == f->local->port)
	       && (lsh_string_cmp(f->local->ip, bind_host) == 0) )
	    {
              verbose("An already requested tcp-forward requested again\n");
              return want_reply ? A_WRITE(connection->write, format_global_failure()):
		LSH_OK | LSH_GOON;
            }
        }

      verbose("Adding forward-tcpip\n");
      port = make_forwarded_port(a);
      
      o = make_forward_listen(make_simple_listen(self->backend, 
                                                 connection->resources),
                              make_open_tcpip_command(connection, port));

      /* FIXME: !!!HERE!!! */
      /* port->listen =  */
      object_queue_add_tail(connection->forwarded_ports, (struct lsh_object *) port);
      return LSH_OK | LSH_GOON;  
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

static int do_cancel_tcpip_forward(struct global_request *c UNUSED, 
				   struct ssh_connection *connection,
				   int want_reply, 
				   struct simple_buffer *args)
{
  UINT32 bind_host_length;
  UINT8 *bind_host;
  UINT32 bind_port;
  
  if (parse_string(args, &bind_host_length, &bind_host) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      FOR_OBJECT_QUEUE(connection->forwarded_ports, n)
        {
          CAST(forwarded_port, f, n);

	  if ( (bind_port == f->local->port)
	       && (lsh_string_cmp_l(f->local->ip, bind_host_length, bind_host) == 0) )
	    {
              verbose("Cancelling a requested tcpip-forward.\n");
	      if (f->socket)
		{
		  close_fd(f->socket, 0);
		  f->socket = NULL;
		  FOR_OBJECT_QUEUE_REMOVE(n);

		  return want_reply
		    ? A_WRITE(connection->write, format_global_success()) 
		    : LSH_OK | LSH_GOON;
		  
		}
	      else
		{
		  werror("cancel_tcpip_forward: Port recognized, but no socket. Cancelled already?\n");
		  break;
		}
            }
	}
      verbose("Could not find tcpip-forward to cancel\n");
      return want_reply ? A_WRITE(connection->write, format_global_failure())
      			: LSH_OK | LSH_GOON;
    }
  else
    {
      werror("Incorrectly formatted cancel-tcpip-forward request\n");
      return LSH_FAIL | LSH_CLOSE;
    }
  return LSH_OK | LSH_GOON;
}

struct global_request *make_cancel_tcpip_forward_request(void)
{
  NEW(global_request, self);
  
  self->handler = do_cancel_tcpip_forward;
  return self;
}

#if 0

static struct fd_callback *
make_tcpip_connected(struct tcpip_channel *c,
		     struct channel_open_callback *response,
		     UINT32 block_size);


/* Connect callback */
/* ;; GABA:
   (class
     (name tcpip_connected)
     (super fd_callback)
     (vars 
       (channel object tcpip_channel)
       (backend object io_backend)
       (block_size simple UINT32)
       (response object channel_open_callback)))
*/

static int do_tcpip_connected(struct fd_callback **c,
                              int fd)
{
  CAST(tcpip_connected, self, *c);

  self->channel->super.receive = do_tcpip_receive;
  self->channel->super.send = do_tcpip_send;
  self->channel->super.eof = do_tcpip_eof;
  
  self->channel->socket = 
     io_read_write(make_io_fd(self->backend, fd), 
		   make_channel_read_data(&self->channel->super), 
		   self->block_size,
		   make_channel_close(&self->channel->super));

  REMEMBER_RESOURCE(self->response->connection->resources,
		    &self->channel->socket->super.super);
  return CHANNEL_OPEN_CALLBACK(self->response, &self->channel->super,
			       0, NULL, NULL);
}

static struct fd_callback *
make_tcpip_connected(struct tcpip_channel *channel,
		     struct channel_open_callback *response,
		     UINT32 block_size)
{
  NEW(tcpip_connected, self);
  
  self->super.f = do_tcpip_connected;
  self->channel = channel;
  self->response = response;
  self->block_size = block_size;
  return &self->super;
}

/* ;;GABA:
   (expr
     (name make_tcpforward)
     (globals
        (start-io COMMAND_UNIMPLEMENTED)
        (listen COMMAND_UNIMPLEMENTED)
	(open-direct-tcpip COMMAND_UNIMPLEMENTED))
     (expr (lambda (port connection)
              (start-io (listen port connection)
	                (open-direct-tcpip connection)))))
*/

/* FIXME: This code requires some mechanism for the server to send a
 * request (in this case, a CHANNEL_OPEN for a forwarded-tcp channel,
 * and wait for client to respond). The problem is similar to the
 * request_info mechanism in client.c. The command.h mechanism may be
 * able to solve the problem in a general way, but tat is currently in
 * the design phase. */

/* Accept callback */
/* ;; GABA:
   (class
     (name tcpip_accepted)
     (super fd_callback)
     (vars
       (block_size simple UINT32)
       (backend object io_backend)))
*/

static int do_tcpip_accepted(struct fd_callback **r, int fd)
{
  CAST(tcpip_accepted, self, *r);
  struct tcpip_channel *channel;
  
  channel = make_tcpip_channel();
  channel->super.receive = do_tcpip_receive;
  channel->super.send = do_tcpip_send;
  channel->super.eof = do_tcpip_eof;
  channel->socket = 
     io_read_write(self->backend, fd, 
		   make_channel_read_data(&channel->super),
		   self->block_size,
		   make_channel_close(&channel->super));
  /* FIXME: Send a forwarded-tcpip request to the peer */
  fatal("Not implemented\n");
}

static struct fd_callback *
make_tcpip_accepted(struct io_backend *backend, UINT32 block_size)
{
  NEW(tcpip_accepted, self);
  
  self->super.f = do_tcpip_accepted;
  self->backend = backend;
  self->block_size = block_size;
  return &self->super;
}

/* forwarded_tcpip */

static struct forwarded_tcpip *
make_forwarded_tcpip(struct lsh_string *bind_host,
		     UINT32 bind_port, struct listen_fd *listen)
{
  NEW(forwarded_tcpip, self);
  
  self->bind_host = bind_host;
  self->bind_port = bind_port;
  self->listen = listen;
  
  return self;
}

/* ;; CLASS:
   (class
     (name tcpip_forward_request)
     (super global_request)
     (vars
       (backend object io_backend)))
*/

static int do_tcpip_forward_request(struct global_request *c, 
				    struct ssh_connection *connection,
				    int want_reply UNUSED, 
				    struct simple_buffer *args)
{
  CAST(tcpip_forward_request, self, c);
  UINT8 *bind_host;
  UINT32 bind_host_length;
  UINT32 bind_port;
  
  if (parse_string(args, &bind_host_length, &bind_host)
      && parse_uint32(args, &bind_port) 
      && parse_eod(args))
    {
      /* struct forwarded_tcpip *f; */
      struct 
      struct listen_fd *listen;
      struct sockaddr_in sin;
      
      f = connection->tcp_forwards;
      while (f && memcmp(f->bind_host->data, bind_host->data, bind_host->length))
        {
          f = f->next;
        }
      if (!f)
        {
          bind_host = make_cstring(bind_host, 1);
          if (get_inaddr(&sin, bind_host->data, NULL, "tcp"))
            {
              listen = io_listen(self->backend, &sin, make_tcpip_accepted(self->backend, SSH_MAX_PACKET));
              if (listen)
                {
                  f = make_forwarded_tcpip(bind_host, bind_port, listen);
                  f->next = connection->tcp_forwards;
                  connection->tcp_forwards = f;
              
                  return A_WRITE(connection->write, format_global_success());
                }
            }
        }
      else
        {
          verbose("an already requested tcp-forward requested again\n");
        }
      return A_WRITE(connection->write, format_global_failure());
    }
  else
    {
      werror("incorrectly formatted tcpip-forward request\n");
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

static int do_cancel_tcpip_forward(struct global_request *c UNUSED, 
		struct ssh_connection *connection,
		int want_reply UNUSED, 
		struct simple_buffer *args)
{
  struct lsh_string *bind_host;
  UINT32 bind_port;
  
  if ((bind_host = parse_string_copy(args)) &&
      parse_uint32(args, &bind_port) &&
      parse_eod(args))
    {
      struct forwarded_tcpip *f, *fprev;
      
      f = connection->tcp_forwards;
      fprev = NULL;
      while (f && memcmp(f->bind_host->data, bind_host->data, bind_host->length))
        {
          fprev = f;
          f = f->next;
        }
      if (f)
        {
          close_fd(&f->listen->super, 0);
          if (fprev)
            fprev->next = f->next;
        }
      else
        {
          werror("unknown tcp forward cancelled\n");
        }
    }
  else
    {
      werror("incorrectly formatted cancel-tcpip-forward request\n");
      return LSH_FAIL | LSH_CLOSE;
    }
  return LSH_OK | LSH_GOON;
}

struct global_request *make_cancel_tcpip_forward_request(void)
{
  NEW(global_request, self);
  
  self->handler = do_cancel_tcpip_forward;
  return self;
}

/* ;;GABA:
   (expr
     (name make_forward_connect)
     (params
       (connect object command)
       (start_io object command))
     (expr
       (lambda (port) (start_io (connect port)))))
*/

#endif
