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

#include <assert.h>
#include <errno.h>
#include <string.h>


#define GABA_DEFINE
#include "tcpforward.h.x"
#undef GABA_DEFINE

#include "tcpforward.c.x"

/* Structures used to keep track of forwarded ports */

static struct local_port *
make_local_port(struct address_info *address, struct lsh_fd *socket)
{
  NEW(local_port, self);

  self->super.listen = address;  
  self->socket = socket;
  return self;
}

struct remote_port *
make_remote_port(struct address_info *listen,
		 struct command *callback)
{
  NEW(remote_port, self);

  self->super.listen = listen;  
  self->callback = callback;

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

static void
do_tcpip_receive(struct ssh_channel *c,
		 int type, struct lsh_string *data)
{
  CAST(tcpip_channel, closure, c);
  
  switch (type)
    {
    case CHANNEL_DATA:
      /* FIXME: What exception handler should we use? */
      A_WRITE(&closure->socket->write_buffer->super, data, &default_exception_handler);
      break;
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      break;
    default:
      fatal("Internal error. do_tcpip_receive()");
    }
}

static void
do_tcpip_send(struct ssh_channel *c)
{
  CAST(tcpip_channel, closure, c);
  
  closure->socket->super.want_read = 1;
}

static void
do_tcpip_eof(struct ssh_channel *c)
{
  if ( (c->flags & CHANNEL_SENT_EOF)
       && (c->flags & CHANNEL_CLOSE_AT_EOF))
    channel_close(c);
}

static void
do_tcpip_channel_die(struct ssh_channel *c)
{
  CAST(tcpip_channel, channel, c);

  if (channel->socket)
    kill_fd(&channel->socket->super);
}

struct ssh_channel *make_tcpip_channel(struct io_fd *socket, UINT32 max_window)
{
  NEW(tcpip_channel, self);
  assert(socket);
  
  init_channel(&self->super);

  self->super.close = do_tcpip_channel_die;

  self->super.max_window = max_window;
  self->super.rec_window_size = max_window;

  /* FIXME: Make maximum packet size configurable. */
  self->super.rec_max_packet = SSH_MAX_PACKET;
  
  self->socket = socket;
  
  return &self->super;
}

void tcpip_channel_start_io(struct ssh_channel *c)
{
  CAST(tcpip_channel, channel, c);

  channel->super.receive = do_tcpip_receive;
  channel->super.send = do_tcpip_send;
  channel->super.eof = do_tcpip_eof;

  /* Install callbacks on the local socket */
  io_read_write(channel->socket,
		make_channel_read_data(&channel->super),
		/* FIXME: Make this configurable */
		SSH_MAX_PACKET * 10, /* self->block_size, */
		make_channel_close(&channel->super));

  /* Start receiving */
  channel_start_receive(&channel->super);
  
  /* Flow control */
  channel->socket->write_buffer->report = &channel->super.super;
}


/* Handle channel open requests */

/* GABA:
   (class
     (name open_forwarded_tcpip_continuation)
     (super command_frame)
     (vars
       (connection object ssh_connection)))
*/

static void
do_open_forwarded_tcpip_continuation(struct command_continuation *s,
				     struct lsh_object *x)
{
  CAST(open_forwarded_tcpip_continuation, self, s);
  CAST_SUBTYPE(ssh_channel, channel, x);

  if (channel)
    {
      channel->write = self->connection->write;
      tcpip_channel_start_io(channel);

      COMMAND_RETURN(self->super.up, channel);
    }
  else
    EXCEPTION_RAISE(self->super.e,
		    make_channel_open_exception(SSH_OPEN_CONNECT_FAILED,
						NULL));
}

static struct command_continuation *
make_open_forwarded_tcpip_continuation(struct ssh_connection *connection,
				       struct command_continuation *c,
				       struct exception_handler *e)
{
  NEW(open_forwarded_tcpip_continuation, self);
  self->super.super.c = do_open_forwarded_tcpip_continuation;
  self->super.up = c;
  self->super.e = e;
  self->connection = connection;

  return &self->super.super;
}

/* GABA:
   (class
     (name channel_open_direct_tcpip)
     (super channel_open)
     (vars
       (callback object command)))
*/

static void
do_channel_open_direct_tcpip(struct channel_open *s,
			     struct ssh_connection *connection,
			     struct simple_buffer *args,
			     struct command_continuation *c,
			     struct exception_handler *e)
{
  CAST(channel_open_direct_tcpip, closure, s);

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
      verbose("direct-tcpip connection attempt\n");

      COMMAND_CALL
	(closure->callback,
	 make_address_info(dest_host, dest_port),
	 make_open_forwarded_tcpip_continuation(connection, c, e),
	 /* FIXME: Which exception handler should we use? */
	 &default_exception_handler /* make_open_forwarded_tcpip_raise(response) */);
    }
  else
    {
      lsh_string_free(dest_host);
      
      werror("do_channel_open_direct_tcpip: Invalid message!\n");
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Invalid CHANNEL_OPEN direct-tcp message."));
    }
}

struct channel_open *
make_channel_open_direct_tcpip(struct command *callback)
{
  NEW(channel_open_direct_tcpip, self);
  
  self->super.handler = do_channel_open_direct_tcpip;
  self->callback = callback;
  return &self->super;
}


/* Global requests for forwarding */

/* GABA:
   (class
     (name tcpip_forward_request_continuation)
     (super command_continuation)
     (vars
       (connection object ssh_connection)
       (forward object local_port)
       (c object global_request_callback)))
*/

/* FIXME: Split off an exception handler */
static void
do_tcpip_forward_request_continuation(struct command_continuation *c,
				      struct lsh_object *x)
{
  CAST(tcpip_forward_request_continuation, self, c);
  CAST_SUBTYPE(lsh_fd, fd, x);

  assert(self->forward);
  
  if (!fd)
    {
      struct local_port *port
	= remove_forward(&self->connection->table->local_ports,
			 1,
			 self->forward->super.listen->ip->length,
			 self->forward->super.listen->ip->data,
			 self->forward->super.listen->port);
      assert(port);
      assert(port == self->forward);
      
      GLOBAL_REQUEST_CALLBACK(self->c, 0);
    }
  
  REMEMBER_RESOURCE(self->connection->resources, &fd->super);

  self->forward->socket = fd;

  GLOBAL_REQUEST_CALLBACK(self->c, 1);
}

static struct command_continuation *
make_tcpip_forward_request_continuation(struct ssh_connection *connection,
					struct local_port *forward,
					struct global_request_callback *c)
{
  NEW(tcpip_forward_request_continuation, self);

  self->connection = connection;
  self->forward = forward;
  self->c = c;
  
  self->super.c = do_tcpip_forward_request_continuation;

  return &self->super;
}


/* GABA:
   (class
     (name tcpip_forward_request)
     (super global_request)
     (vars
       (callback object command)))
       ;; (backend object io_backend)))
*/

static void
do_tcpip_forward_request(struct global_request *s, 
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
	  GLOBAL_REQUEST_CALLBACK(c, 0);
	  return;
	}

      if (lookup_forward(&connection->table->local_ports,
			 bind_host->length, bind_host->data, bind_port))
	{
	  verbose("An already requested tcp-forward requested again\n");
	  GLOBAL_REQUEST_CALLBACK(c, 0);
	  return;
	}
      
      verbose("Adding forward-tcpip\n");
      forward = make_local_port(a, NULL);
      object_queue_add_head(&connection->table->local_ports,
			    &forward->super.super);

      {
	COMMAND_CALL(self->callback,
		     a,
		     make_tcpip_forward_request_continuation
		     (connection, forward, c), 
		     &default_exception_handler
		     /* make_tcpip_forward_request_raise
			(connection, forward) */ );
	return;
      }
    }
  else
    {
      werror("Incorrectly formatted tcpip-forward request\n");
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Invalid tcpip-forward message."));
    }
}

struct global_request *make_tcpip_forward_request(struct command *callback)
{
  NEW(tcpip_forward_request, self);
  
  self->super.handler = do_tcpip_forward_request;
  self->callback = callback;
  
  return &self->super;
}

static void
do_tcpip_cancel_forward(struct global_request *s UNUSED, 
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
      /* FIXME: using null_ok == 0 is not quite right, if the
       * forwarding was requested with want_reply == 0 */
      struct local_port *port
	= remove_forward(&connection->table->local_ports, 0,
			 bind_host_length,
			 bind_host,
			 bind_port);

      if (port)
        {
	  assert(port->socket);
	  verbose("Cancelling a requested tcpip-forward.\n");

	  close_fd(port->socket, 0);
	  port->socket = NULL;

	  GLOBAL_REQUEST_CALLBACK(c, 1);
	  return;
	}
      else
	{      
	  verbose("Could not find tcpip-forward to cancel\n");

	  GLOBAL_REQUEST_CALLBACK(c, 0);
	  return;
	}
    }
  else
    {
      werror("Incorrectly formatted cancel-tcpip-forward request\n");
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Invalid cancel-tcpip-forward message."));
    }
}

struct global_request tcpip_cancel_forward =
{ STATIC_HEADER, do_tcpip_cancel_forward }; 


/* Remote forwarding */

static void
do_channel_open_forwarded_tcpip(struct channel_open *s UNUSED,
				struct ssh_connection *connection,
				struct simple_buffer *args,
				struct command_continuation *c,
				struct exception_handler *e)
{
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
	   lookup_forward(&connection->table->remote_ports,
			  listen_ip_length, listen_ip, listen_port));
	   
      if (port && port->callback)
	{
	  COMMAND_CALL(port->callback,
		       make_address_info(peer_host, peer_port),
		       make_open_forwarded_tcpip_continuation(connection, c, e),
		       /* FIXME: Use a better exception handler */
		       &default_exception_handler
		       /* make_open_forwarded_tcpip_raise(response) */);
	  return;
	}
      werror("Received a forwarded-tcpip request on a port for which we\n"
	     "haven't requested forwarding. Denying.\n");

      lsh_string_free(peer_host);
      EXCEPTION_RAISE(e,
		      make_channel_open_exception(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
						  "Unexpected tcpip-forward request"));
      return;
    }
  else
    {
      werror("do_channel_open_forwarded_tcpip: Invalid message!\n");

      lsh_string_free(peer_host);
      EXCEPTION_RAISE(e, make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
						 "Invalid tcpip-forward message"));
    }
}

struct channel_open channel_open_forwarded_tcpip =
{ STATIC_HEADER, do_channel_open_forwarded_tcpip};
