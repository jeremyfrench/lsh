/* proxy_channel.c
 *
 * $Id$ */

#warning proxy_channel.c is obsolete; replaced by gateway_channel.c

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

#include "proxy_channel.h"

#include "channel_commands.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "proxy_channel.h.x"
#undef GABA_DEFINE

#include "proxy_channel.c.x"

#define WINDOW_SIZE 10000

static void
do_receive(struct ssh_channel *c,
	   int type,
	   struct lsh_string *data)
{
  CAST(proxy_channel, closure, c);
  
  switch(type)
    {
    case CHANNEL_DATA:
      A_WRITE(closure->chain->super.write, channel_transmit_data(&closure->chain->super, data));
      break;
    case CHANNEL_STDERR_DATA:
      A_WRITE(closure->chain->super.write, channel_transmit_extended(&closure->chain->super, CHANNEL_STDERR_DATA, data));
      break;
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static void
do_send_adjust(struct ssh_channel *s,
	       UINT32 i)
{
  CAST(proxy_channel, self, s);
  FLOW_CONTROL_REPORT(&self->chain->super.super, i);
}

static void
do_eof(struct ssh_channel *c)
{
  CAST(proxy_channel, channel, c);
  channel_eof(&channel->chain->super);
}

static void
do_close(struct ssh_channel *c)
{
  CAST(proxy_channel, channel, c);  
  channel_close(&channel->chain->super);
}

static void 
do_init_io(struct proxy_channel *self)
{
  self->super.send_adjust = do_send_adjust;  
  self->super.receive = do_receive;
  self->super.eof = do_eof;
  self->super.close = do_close;
}

/* NOTE: It seems most calls doesn't provide the correct value for
 * rec_max_packet. In these cases, it should probably be filled in
 * later, by do_proxy_channel_open_continuation fill it in later. */
struct proxy_channel *
make_proxy_channel(UINT32 window_size,
		   UINT32 rec_max_packet,
		   struct alist *request_types,
		   int client_side)
{
  NEW(proxy_channel, self);
  init_channel(&self->super);

  self->super.max_window = SSH_MAX_PACKET << 3;
  self->super.rec_window_size = window_size;
  self->super.rec_max_packet = rec_max_packet;
  self->super.request_types = request_types;
  self->init_io = do_init_io;

  /* Never initiate close; let each end point decide when it is time
   * to send SSH_MSG_CHANNEL_CLOSE. */
  self->super.flags &= ~CHANNEL_CLOSE_AT_EOF;

  return self;
}

/* proxy channel requests */

/* GABA:
   (class
     (name general_channel_request_command)
     (super channel_request_command)
     (vars
       (request string)))
*/

static struct lsh_string *
do_format_channel_general(struct channel_request_command *s,
			  struct ssh_channel *ch UNUSED,
			  struct command_continuation **c UNUSED)
{
  CAST(general_channel_request_command, self, s);

  struct lsh_string *r = self->request;
  self->request = NULL;
  return r;
}

static struct command *
make_general_channel_request_command(struct lsh_string *request)
{
  NEW(general_channel_request_command, self);
  self->super.super.call = do_channel_request_command;
  self->super.format_request = do_format_channel_general;
  self->request = request;
  return &self->super.super;
}

static void 
do_proxy_channel_request(struct channel_request *s UNUSED,
			 struct ssh_channel *ch,
			 struct ssh_connection *connection UNUSED,
			 UINT32 type,
			 int want_reply,
			 struct simple_buffer *args,
			 struct command_continuation *c,
			 struct exception_handler *e)
{
  CAST(proxy_channel, channel, ch);

  struct lsh_string *request = 
    format_channel_request(type, &channel->chain->super, want_reply, 
			   "%ls", 
			   args->capacity - args->pos, &args->data[args->pos]);
  struct command *send;

  send = make_general_channel_request_command(request);

  COMMAND_CALL(send, channel->chain, c, e);
}

struct channel_request proxy_channel_request =
{ STATIC_HEADER, do_proxy_channel_request };

/* GABA:
   (class
     (name general_global_request_command)
     (super global_request_command)
     (vars
       (request string)))
*/

static struct lsh_string *
do_format_general_global_request(struct global_request_command *s,
			  	 struct ssh_connection *connection UNUSED,
				 struct command_continuation **c UNUSED)
{
  CAST(general_global_request_command, self, s);

  struct lsh_string *r = self->request;
  self->request = NULL;
  return r;
}

static struct command *
make_general_global_request_command(struct lsh_string *request)
{
  NEW(general_global_request_command, self);
  
  self->super.super.call = do_channel_global_command;
  self->super.format_request = do_format_general_global_request;
  self->request = request;
  return &self->super.super;
}

static void
do_proxy_global_request(struct global_request *s UNUSED,
			struct ssh_connection *connection,
                        UINT32 type,
                        int want_reply,
                        struct simple_buffer *args,
			struct command_continuation *c,
			struct exception_handler *e)
{
  struct lsh_string *request =
    format_global_request(type, want_reply, "%ls", 
			  args->capacity - args->pos, &args->data[args->pos]);

  struct command *send;

  send = make_general_global_request_command(request);

  COMMAND_CALL(send, connection->chain, c, e);
}

struct global_request proxy_global_request = 
{ STATIC_HEADER, do_proxy_global_request };

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
  chain_channel->chain = self->channel;

  /* FIXME: I think this is the right thing to do, but I'm not quite
   * sure. /nisse */

  /* self->channel->rec_max_packet = chain_channel->send_max_packet; */
  
  PROXY_CHANNEL_INIT_IO(self->channel);
  PROXY_CHANNEL_INIT_IO(chain_channel);
    
  COMMAND_RETURN(self->up, self->channel);
}

struct command_continuation *
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
       (type . int)
       (max_packet . UINT32)
       (requests object alist)
       (open_request string)))
*/

static struct ssh_channel *
do_proxy_channel_open(struct channel_open_command *c,
		      struct ssh_connection *connection,
		      UINT32 local_channel_number,
		      struct lsh_string **request)
{
  CAST(proxy_channel_open_command, closure, c);
  
  struct proxy_channel *client
    = make_proxy_channel(WINDOW_SIZE, closure->max_packet,
			 closure->requests, 1);

  client->super.write = connection->write;
  
  if (closure->open_request)
    *request = format_channel_open(closure->type, local_channel_number,
				   &client->super, "%lS", closure->open_request);
  else
    *request = format_channel_open(closure->type, local_channel_number,
				   &client->super, "");
  
  return &client->super;
}

struct command *
make_proxy_channel_open_command(int type,
				UINT32 max_packet,
                                struct lsh_string *open_request,
				struct alist *requests)
{
  NEW(proxy_channel_open_command, self);
  
  self->super.new_channel = do_proxy_channel_open;
  self->super.super.call = do_channel_open_command;
  self->type = type;
  self->max_packet = max_packet;
  self->requests = requests;
  self->open_request = open_request;

  return &self->super.super;
}
