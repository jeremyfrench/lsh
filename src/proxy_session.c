/* proxy_session.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "proxy_session.h"
#include "xalloc.h"
#include "ssh.h"
#include "werror.h"
#include "channel_commands.h"

#include "proxy_session.c.x"

#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

/* GABA:
   (class
     (name proxy_channel)
     (super ssh_channel)
     (vars
       (chain object proxy_channel)
       (init_io method void "struct proxy_channel *chain")))
*/

static void
do_receive(struct ssh_channel *c UNUSED,
	   int type UNUSED,
	   struct lsh_string *data UNUSED)
{
}

static void
do_send(struct ssh_channel *s UNUSED,
	struct ssh_connection *c UNUSED)
{
}

static void
do_eof(struct ssh_channel *channel UNUSED)
{
}

static void
do_proxy_init_io(struct proxy_channel *self,
		 struct proxy_channel *chain)
{
  self->chain = chain;
  self->super.send = do_send;
  self->super.receive = do_receive;
  self->super.eof = do_eof;
}


static struct proxy_channel *
make_proxy_channel(UINT32 window_size,
		   struct alist *request_types)
{
  NEW(proxy_channel, self);
  init_channel(&self->super);

  self->super.max_window = SSH_MAX_PACKET << 3;
  self->super.rec_window_size = window_size;
  self->super.rec_max_packet = SSH_MAX_PACKET;
  self->super.request_types = request_types;
  self->init_io = do_proxy_init_io;
  return self;
}

/*
 * continuation to handle the returned channel, and chain two channels
 * together
 */

/* GABA:
   (class
     (name proxy_channel_open_continuation)
     (super command_continuation)
     (vars
       (up object command_continuation)
       (channel object proxy_channel)))
*/

static void
do_proxy_channel_open_continuation(struct command_continuation *c,
				   struct lsh_object *x)
{
  CAST(proxy_channel_open_continuation, self, c);
  CAST(proxy_channel, chain_channel, x);

  self->channel->chain = chain_channel;
  chain_channel = self->channel;
    
  COMMAND_RETURN(self->up, self->channel);
}

static struct command_continuation *
make_proxy_channel_open_continuation(struct command_continuation *up,
				     struct proxy_channel *channel)
{
  NEW(proxy_channel_open_continuation, self);
  
  self->super.c = do_proxy_channel_open_continuation;
  self->channel = channel;
  self->up = up;
  return &self->super;
}

/* command to request a channel open */
/* GABA:
   (class
     (name proxy_channel_open_command)
     (super channel_open_command)
     (vars
       ; channel type
       (type . UINT32)
       (requests object alist)))
*/

static struct ssh_channel *
do_proxy_open_channel(struct channel_open_command *c,
		      struct ssh_connection *connection UNUSED,
		      UINT32 local_channel_number,
		      struct lsh_string **request)
{
  CAST(proxy_channel_open_command, closure, c);
  
  struct proxy_channel *client = make_proxy_channel(WINDOW_SIZE, closure->requests);
  
  *request = format_channel_open(closure->type, local_channel_number, &client->super, "");
  
  return &client->super;
}

static struct command *
make_proxy_channel_open_command(UINT32 type,
				struct alist *requests)
{
  NEW(proxy_channel_open_command, self);
  
  self->super.new_channel = do_proxy_open_channel;
  self->super.super.call = do_channel_open_command;
  self->type = type;
  self->requests = requests;
  return &self->super.super;
}


/* GABA:
   (class
     (name proxy_open_session)
     (super channel_open)
     (vars
       ; requests to accept from server -> client
       (server_requests object alist)
       ; requests to accept from client -> server
       (client_requests object alist)))

*/

static void
do_proxy_open_session(struct channel_open *s,
		      struct ssh_connection *connection,
		      UINT32 type,
		      struct simple_buffer *args,
		      struct command_continuation *c,
		      struct exception_handler *e)
{
  CAST(proxy_open_session, closure, s);

  debug("server.c: do_proxy_open_session()\n");

  if (parse_eod(args))
    {
      struct proxy_channel *server = make_proxy_channel(WINDOW_SIZE, closure->server_requests);
      struct command *o = make_proxy_channel_open_command(type, closure->client_requests);

      COMMAND_CALL(o,
		   connection->chain,
		   make_proxy_channel_open_continuation(c, server),
		   e);

    }
  else
    {
      PROTOCOL_ERROR(e, "Trailing garbage in open message");
    }
}

struct channel_open *
make_proxy_open_session(struct alist *server_requests,
			struct alist *client_requests)
{
  NEW(proxy_open_session, self);

  self->super.handler = do_proxy_open_session;
  self->server_requests = server_requests;
  self->client_requests = client_requests;
  return &self->super;
}
