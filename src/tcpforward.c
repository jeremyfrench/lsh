/* tcpforward.h
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

#include "command.h"
#include "format.h"
#include "parse.h"
#include "read_data.h"
#include "ssh.h"
#include "werror.h"

#include <errno.h>
#include <string.h>

#define GABA_DEFINE
#include "tcpforward.h.x"
#undef GABA_DEFINE

#include "tcpforward.c.x"

static struct fd_callback *
make_tcpip_connected(struct tcpip_channel *c,
		     struct channel_open_callback *response,
		     UINT32 block_size);

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
/* GABA:
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
  UINT8 *dest_host;
  UINT32 dest_host_length;
  UINT32 dest_port;
  UINT8 *orig_host;
  UINT32 orig_host_length;
  UINT32 orig_port;
  
  if (parse_string(args, &dest_host_length, &dest_host)
      && parse_uint32(args, &dest_port) 
      && parse_string(args, &orig_host_length, &orig_host)
      && parse_uint32(args, &orig_port) 
      && parse_eod(args))
    {
      struct connect_fd *connect;
      struct sockaddr_in sin;
      
      verbose("direct-tcp connection attempt\n");
      
      /* FIXME: implement filtering on original host? */

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
					   strerror(errno),
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

/* GABA:
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
#if 0
/* FIXME: This code requires some mechanism for the server to send a
 * request (in this case, a CHANNEL_OPEN for a forwarded-tcp channel,
 * and wait for client to respond). The problem is similar to the
 * request_info mechanism in client.c. The command.h mechanism may be
 * able to solve the problem in a general way, but tat is currently in
 * the design phase. */

/* Accept callback */
/* xxCLASS:
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

/* xxCLASS:
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
#endif /* 0 */
