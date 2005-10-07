/* tcpforward.c
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

#include "channel_commands.h"
#include "channel_forward.h"
#include "format.h"
#include "io_commands.h"
#include "lsh_string.h"
#include "ssh.h"

#include "werror.h"


#define GABA_DEFINE
#include "tcpforward.h.x"
#undef GABA_DEFINE

#include "tcpforward.c.x"

/* Structures used to keep track of forwarded ports */

#if 0
static struct remote_port *
make_remote_port(struct address_info *listen,
		 struct command *callback)
{
  NEW(remote_port, self);

  self->super.listen = listen;  
  self->callback = callback;

  return self;
}
#endif

struct forwarded_port *
tcpforward_lookup(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST_SUBTYPE(forwarded_port, f, n);
      
      if ( (port == f->address->port)
	   && lsh_string_eq_l(f->address->ip, length, ip) )
	return f;
    }
  return NULL;
}

int
tcpforward_remove_port(struct object_queue *q, struct forwarded_port *port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST_SUBTYPE(forwarded_port, f, n);
      
      if (port == f)
	{
	  FOR_OBJECT_QUEUE_REMOVE(q, n);
	  return 1;
	}
    }
  return 0;
}

/* GABA:
   (class
     (name tcpforward_connect_state)
     (super io_connect_state)
     (vars
       (c object command_continuation)
       (e object exception_handler)))
*/

static void
tcpforward_connect_done(struct io_connect_state *s, int fd)
{
  CAST(tcpforward_connect_state, self, s);

  COMMAND_RETURN(self->c, make_channel_forward(fd, TCPIP_WINDOW_SIZE));
}

static void
tcpforward_connect_error(struct io_connect_state *s, int error)
{
  CAST(tcpforward_connect_state, self, s);
  
  werror("Connection failed, socket error %i\n", error);
  EXCEPTION_RAISE(self->e,
		  make_exception(EXC_CHANNEL_OPEN, error, "Connection failed"));
}

struct resource *
tcpforward_connect(struct address_info *a,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  struct sockaddr *addr;
  socklen_t addr_length;

  addr = io_make_sockaddr(&addr_length, lsh_get_cstring(a->ip), a->port);
  if (!addr)
    {
      EXCEPTION_RAISE(e, make_exception(EXC_RESOLVE, 0, "invalid address"));
      return NULL;
    }

  {
    NEW(tcpforward_connect_state, self);
    init_io_connect_state(&self->super,
			  tcpforward_connect_done,
			  tcpforward_connect_error);
    int res;
    
    self->c = c;
    self->e = e;

    res = io_connect(&self->super, addr_length, addr);
    lsh_space_free(addr);

    if (!res)
      {
	EXCEPTION_RAISE(e, make_exception(EXC_IO_ERROR, errno, "io_connect failed"));
	return NULL;
      }
    return &self->super.super;
  }
}

#if 0
/* Handle channel open requests */

/* Exception handler that promotes connect and dns errors to
 * CHANNEL_OPEN exceptions */

static void
do_exc_tcip_connect_handler(struct exception_handler *s,
			    const struct exception *e)
{
  switch(e->type)
    {
    case EXC_IO_CONNECT:
    case EXC_RESOLVE:
      EXCEPTION_RAISE(s->parent,
		      make_channel_open_exception(SSH_OPEN_CONNECT_FAILED,
						  e->msg));
      break;
    default:
      EXCEPTION_RAISE(s->parent, e);
    }
}

static struct exception_handler *
make_exc_tcpip_connect_handler(struct exception_handler *parent,
			       const char *context)
{
  return make_exception_handler(do_exc_tcip_connect_handler, parent, context);
}

/* GABA:
   (class
     (name open_forwarded_tcpip_continuation)
     (super command_continuation)
     (vars
       (up object command_continuation)))
*/

/* NOTE: This continuation should not duplicate the work done by
 * channel_open_continuation. It must also not send any packets on the
 * channel, because it is not yet completely initialized. */
static void
do_open_forwarded_tcpip_continuation(struct command_continuation *s,
				     struct lsh_object *x)
{
  CAST(open_forwarded_tcpip_continuation, self, s);
  CAST(channel_forward, channel, x);

  assert(channel);

  channel_forward_start_io(channel);

  COMMAND_RETURN(self->up, channel);
}

static struct command_continuation *
make_open_forwarded_tcpip_continuation(struct command_continuation *c)
{
  NEW(open_forwarded_tcpip_continuation, self);
  self->super.c = do_open_forwarded_tcpip_continuation;
  self->up = c;

  return &self->super;
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
			     struct channel_table *table,
			     struct channel_open_info *info UNUSED,
			     struct simple_buffer *args,
			     struct command_continuation *c,
			     struct exception_handler *e)
{
  CAST(channel_open_direct_tcpip, closure, s);

  struct lsh_string *dest_host;
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
#if 0
      werror("direct-tcp to %S:%i for user %S.\n",
	     dest_host, dest_port, connection->user->name);
#endif      
      COMMAND_CALL(closure->callback,
		   make_address_info(dest_host, dest_port),
		   make_open_forwarded_tcpip_continuation(c), 
		   /* NOTE: This exception handler will be associated with the
		    * fd for its entire lifetime. */
		   make_exc_tcpip_connect_handler(e, HANDLER_CONTEXT));
    }
  else
    {
      lsh_string_free(dest_host);
      
      werror("do_channel_open_direct_tcpip: Invalid message!\n");
      PROTOCOL_ERROR(table->e, "Invalid CHANNEL_OPEN direct-tcp message.");
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



/* Remote forwarding */

static void
do_channel_open_forwarded_tcpip(struct channel_open *s UNUSED,
				struct channel_table *table,
				struct channel_open_info *info UNUSED,
				struct simple_buffer *args,
				struct command_continuation *c,
				struct exception_handler *e)
{
  uint32_t listen_ip_length;
  const uint8_t *listen_ip;
  uint32_t listen_port;
  struct lsh_string *peer_host = NULL;
  uint32_t peer_port;

  if (parse_string(args, &listen_ip_length, &listen_ip)
      && parse_uint32(args, &listen_port)
      && (peer_host = parse_string_copy(args))
      && parse_uint32(args, &peer_port)
      && parse_eod(args))
    {
      CAST(remote_port, port,
	   lookup_forward(&table->remote_ports,
			  listen_ip_length, listen_ip, listen_port));
	   
      if (port && port->callback)
	{
	  COMMAND_CALL(port->callback,
		       make_address_info(peer_host, peer_port),
		       make_open_forwarded_tcpip_continuation(c),
		       /* NOTE: This exception handler will be
			* associated with the fd for its entire
			* lifetime. */
		       make_exc_tcpip_connect_handler(e, HANDLER_CONTEXT));
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
      PROTOCOL_ERROR(e, "Invalid tcpip-forward message");
    }
}

struct channel_open channel_open_forwarded_tcpip =
{ STATIC_HEADER, do_channel_open_forwarded_tcpip};
#endif
