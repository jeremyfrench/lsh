/* channel.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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
#include <string.h>

#include "channel.h"

#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "channel.h.x"
#undef GABA_DEFINE

#include "channel.c.x"

/* Opening a new channel: There are two cases, depending on which side
   sends the CHANNEL_OPEN. When we send it, the following
   steps are taken:

   1. Create a new channel object of the appropriate type.
   
   2. Call channel_open_new_v or channel_open_new_type. This allocates
      a channel number, registers the object, and sends a CHANNEL_OPEN
      request.

   3. If the remote end replies with CHANNEL_OPEN_CONFIRMATION, the
      channel's event handler is invoked, with CHANNEL_EVENT_CONFIRM.
      If the remote end replies with CHANNEL_OPEN_FAILURE, then event
      handler is invoked with CHANNEL_EVENT_DENY, and then the channel
      is killed.

   When the other side requests a new channel, the steps are:

   1. Receive CHANNEL_OPEN. Allocate a channel number, and invoke the
      CHANNEL_OPEN method corresponding to the channel type.

   2. The CHANNEL_OPEN method should arrange that channel_open_confirm
      or channel_open_deny are called some time later.

   3. For channel_open_confirm, the given channel is installed, and a
      CHANNEL_OPEN_CONFIRMATION message is sent. For
      channel_open_deny, the channel number is deallocated, and a
      CHANNEL_OPEN_FAILURE message is sent.
*/

struct exception *
make_channel_open_exception(uint32_t error_code, const char *msg)
{
#define MAX_ERROR 4
  static const char *msgs[MAX_ERROR + 1] = {
    "",
    "Administratively prohibited",
    "Connect failed",
    "Unknown channel type",
    "Resource shortage"
  };

  assert(error_code > 0);
  assert(error_code <= MAX_ERROR);
#undef MAX_ERROR

  return make_exception(EXC_CHANNEL_OPEN, error_code,
			msg ? msg : msgs[error_code]);
}


static struct lsh_string *
format_global_failure(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_FAILURE);
}

static struct lsh_string *
format_global_success(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_SUCCESS);
}

/* The advertised rec_max_size must be a little smaller than SSH_MAX_PACKET,
 * to make sure that our peer won't send us packets exceeding our limit for
 * the connection. */

/* NOTE: It would make some sense to use the connection's
 * rec_max_packet instead of the SSH_MAX_PACKET constant. */

#define SSH_MAX_DATA_SIZE (SSH_MAX_PACKET - SSH_CHANNEL_MAX_PACKET_FUZZ)

static void
check_rec_max_packet(struct ssh_channel *channel)
{
  /* Never advertise a larger rec_max_packet than we're willing to
   * handle. */

  if (channel->rec_max_packet > SSH_MAX_DATA_SIZE)
    {
      debug("check_rec_max_packet: Reduced rec_max_packet from %i to %i.\n",
	    channel->rec_max_packet, SSH_MAX_DATA_SIZE);
      channel->rec_max_packet = SSH_MAX_DATA_SIZE;
    }
}

struct lsh_string *
format_open_confirmation(struct ssh_channel *channel,
			 const char *format, ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;
  
#define CONFIRM_FORMAT "%c%i%i%i%i"
#define CONFIRM_ARGS \
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION, \
  channel->remote_channel_number, channel->local_channel_number, \
  channel->rec_window_size, channel->rec_max_packet
    
  check_rec_max_packet(channel);

  debug("format_open_confirmation: rec_window_size = %i,\n"
	"                          rec_max_packet = %i,\n",
       channel->rec_window_size,
       channel->rec_max_packet);
  l1 = ssh_format_length(CONFIRM_FORMAT, CONFIRM_ARGS);

  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(CONFIRM_FORMAT, packet, 0, CONFIRM_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

  return packet;
#undef CONFIRM_FORMAT
#undef CONFIRM_ARGS
}

struct lsh_string *
format_open_failure(uint32_t channel, uint32_t reason,
		    const char *msg, const char *language)
{
  return ssh_format("%c%i%i%z%z", SSH_MSG_CHANNEL_OPEN_FAILURE,
		    channel, reason, msg, language);
}

struct lsh_string *
format_channel_success(uint32_t channel)
{
  return ssh_format("%c%i", SSH_MSG_CHANNEL_SUCCESS, channel);
}

struct lsh_string *
format_channel_failure(uint32_t channel)
{
  return ssh_format("%c%i", SSH_MSG_CHANNEL_FAILURE, channel);
}

static struct lsh_string *
format_channel_data(uint32_t number, uint32_t length, const uint8_t *data)
{
  return ssh_format("%c%i%s", SSH_MSG_CHANNEL_DATA,
		    number, length, data);
}

static struct lsh_string *
format_channel_extended_data(uint32_t number, uint32_t type,
			     uint32_t length, const uint8_t *data)
{
  return ssh_format("%c%i%i%s", SSH_MSG_CHANNEL_EXTENDED_DATA,
		    number, type, length, data);
}

static struct lsh_string *
format_channel_window_adjust(uint32_t number, uint32_t add)
{
  return ssh_format("%c%i%i",
		    SSH_MSG_CHANNEL_WINDOW_ADJUST,
		    number, add);
}

static struct lsh_string *
format_channel_close(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_CLOSE,
		    channel->remote_channel_number);
}

static struct lsh_string *
format_channel_eof(uint32_t number)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_EOF, number);
}

/* Channel objects */

static void
channel_finished(struct ssh_channel *channel)
{
  if (!channel->super.alive)
    werror("channel_finished called on a dead channel.\n");
  else
    {
      struct ssh_connection *connection = channel->connection;

      trace("channel_finished: Deallocating channel %i\n", channel->local_channel_number);
      KILL_RESOURCE(&channel->super);

      /* Disassociate from the connection. */
      channel->connection = NULL;
      
      ssh_connection_dealloc_channel(connection, channel->local_channel_number);

      trace("channel_finished: connection->pending_close = %i,\n"
	    "                  connection->channel_count = %i\n",
	    connection->pending_close, connection->channel_count);

      if (connection->pending_close && !connection->channel_count)
	KILL_RESOURCE(&connection->super);
    }
}

static void
send_window_adjust(struct ssh_channel *channel,
		   uint32_t add)
{
  channel->rec_window_size += add;

  SSH_CONNECTION_WRITE(
    channel->connection,   
    format_channel_window_adjust(channel->remote_channel_number, add));
}

/* FIXME: It seems suboptimal to send a window adjust message for
 * *every* write that we do. A better scheme might be as follows:
 *
 * Delay window adjust messages, keeping track of both the locally
 * maintained window size, which is updated after each write, and the
 * size that has been reported to the remote end. When the difference
 * between these two values gets large enough (say, larger than one
 * half or one third of the maximum window size), we send a
 * window_adjust message to sync them. */
void
channel_adjust_rec_window(struct ssh_channel *channel, uint32_t written)
{
  /* NOTE: The channel object (referenced as a flow-control callback)
   * may live longer than the actual channel. */
  if (written && ! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE
				      | CHANNEL_SENT_CLOSE)))
    send_window_adjust(channel, written);
}

void
channel_start_receive(struct ssh_channel *channel,
		      uint32_t initial_window_size)
{
  if (channel->rec_window_size < initial_window_size)
    send_window_adjust(channel,
		       initial_window_size - channel->rec_window_size);
}

/* Channel related messages */

/* GABA:
   (class
     (name request_status)
     (vars
       ; -1 for still active requests,
       ; 0 for failure,
       ; 1 for success
       (status . int)))
*/

static struct request_status *
make_request_status(void)
{
  NEW(request_status, self);
  self->status = -1;

  return self;
}

/* GABA:
   (class
     (name global_request_continuation)
     (super command_continuation)
     (vars
       (connection object ssh_connection)
       (active object request_status)))
*/

static void 
send_global_request_responses(struct ssh_connection *connection)
{
  struct object_queue *q = &connection->active_global_requests;

  assert(!object_queue_is_empty(q));

  for (;;)
    {
      CAST(request_status, n, object_queue_peek_head(q));
      if (!n || (n->status < 0))
	break;
 
      object_queue_remove_head(q);

      SSH_CONNECTION_WRITE(connection, (n->status
				  ? format_global_success()
				  : format_global_failure()));
    }
}

static void
do_global_request_response(struct command_continuation *s,
			   struct lsh_object *x UNUSED)
{
  CAST(global_request_continuation, self, s);

  assert(self->active->status == -1);
  self->active->status = 1;

  send_global_request_responses(self->connection);
}

static struct command_continuation *
make_global_request_response(struct ssh_connection *connection,
			     struct request_status *active)
{
  NEW(global_request_continuation, self);

  self->super.c = do_global_request_response;
  self->connection = connection;
  self->active = active;
   
  return &self->super;
}


/* GABA:
   (class
     (name global_request_exception_handler)
     (super exception_handler)
     (vars
       (connection object ssh_connection)
       (active object request_status)))
*/

/* All exceptions are treated as a failure. */
static void 
do_exc_global_request_handler(struct exception_handler *c,
			      const struct exception *e)
{
  CAST(global_request_exception_handler, self, c);

  assert(self->active->status == -1);
  self->active->status = 0;

  werror("Denying global request: %z\n", e->msg);
  send_global_request_responses(self->connection);
}

static struct exception_handler *
make_global_request_exception_handler(struct ssh_connection *connection,
				      struct request_status *active,
				      const char *context)
{
  NEW(global_request_exception_handler, self);

  self->super.raise = do_exc_global_request_handler;
  self->super.context = context;
  self->active = active;
  self->connection = connection;
  return &self->super;
}

static void
handle_global_request(struct ssh_connection *connection,
		      struct simple_buffer *buffer)
{
  enum lsh_atom name;
  int want_reply;
  
  if (parse_atom(buffer, &name)
      && parse_boolean(buffer, &want_reply))
    {
      struct global_request *req = NULL;

      if (name && connection->global_requests)
	{
	  CAST_SUBTYPE(global_request, r,
		       ALIST_GET(connection->global_requests,
				 name));
	  req = r;
	}
      if (!req)
	{
	  SSH_CONNECTION_WRITE(connection, format_global_failure());
	  return;
	}
      else
	{
	  struct command_continuation *c;
	  struct exception_handler *e;
	  if (want_reply)
	    {
	      struct request_status *a = make_request_status();
	      
	      object_queue_add_tail(&connection->active_global_requests,
				    &a->super);
	      
	      c = make_global_request_response(connection, a);
	      e = make_global_request_exception_handler(connection, a,
							HANDLER_CONTEXT);
	    }
	  else
	    {
	      /* We should ignore failures. */
	      c = &discard_continuation;
	      e = &ignore_exception_handler;
	    }
	  GLOBAL_REQUEST(req, connection, name, want_reply, buffer, c, e);
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid SSH_MSG_GLOBAL_REQUEST message.");
}

static void
handle_global_success(struct ssh_connection *connection,
		      struct simple_buffer *buffer)
{
  if (!parse_eod(buffer))
    {
      SSH_CONNECTION_ERROR(connection, "Invalid GLOBAL_REQUEST_SUCCESS message.");
      return;
    }

  if (object_queue_is_empty(&connection->pending_global_requests))
    {
      werror("do_global_request_success: Unexpected message, ignoring.\n");
      return;
    }
  {
    CAST_SUBTYPE(command_context, ctx,
		 object_queue_remove_head(&connection->pending_global_requests));
    COMMAND_RETURN(ctx->c, connection);
  }
}

struct exception global_request_exception =
STATIC_EXCEPTION(EXC_GLOBAL_REQUEST, 0, "Global request failed");

static void
handle_global_failure(struct ssh_connection *connection,
		      struct simple_buffer *buffer)
{
  if (!parse_eod(buffer))
    {
      SSH_CONNECTION_ERROR(connection, "Invalid GLOBAL_REQUEST_FAILURE message.");
      return;
    }

  if (object_queue_is_empty(&connection->pending_global_requests))
    {
      werror("do_global_request_failure: Unexpected message, ignoring.\n");
    }
  else
    {
      CAST_SUBTYPE(command_context, ctx,
		   object_queue_remove_head(&connection->pending_global_requests));
      EXCEPTION_RAISE(ctx->e, &global_request_exception);
    }
}

static void
handle_channel_request(struct ssh_connection *connection,
		       struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct channel_request_info info;
  
  if (parse_uint32(buffer, &channel_number)
      &&parse_string(buffer,
		     &info.type_length, &info.type_data)
      && parse_boolean(buffer, &info.want_reply))
    {    
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);
      if (channel)
	{
	  struct channel_request *req = NULL;

	  trace("handle_channel_request: Request type `%ps' on channel %i\n",
		info.type_length, info.type_data, channel_number);

	  info.type = lookup_atom(info.type_length, info.type_data);

	  if (channel->request_types && info.type)
	    {
	      CAST_SUBTYPE(channel_request, r,
			   ALIST_GET(channel->request_types, info.type));
	      req = r;
	    }

	  if (!req)
	    req = channel->request_fallback;

	  if (req)
	    req->handler(req, channel, &info, buffer);
	  else
	    channel_request_reply(channel, &info, 0);

	  return;
	}
      else
	werror("SSH_MSG_CHANNEL_REQUEST on nonexistant channel %i.\n",
	       channel_number);
      /* Fall through to error case. */
    }
  
  SSH_CONNECTION_ERROR(connection,
		       "Invalid SSH_MSG_CHANNEL_REQUEST message.");
}

void
channel_request_reply(struct ssh_channel *channel,
		      const struct channel_request_info *info,
		      int result)
{
  if (info->want_reply)
    {
      struct lsh_string *response
	= (result
	   ? format_channel_success(channel->remote_channel_number)
	   : format_channel_failure(channel->remote_channel_number));
      
      SSH_CONNECTION_WRITE(channel->connection, response);
    }
}


void
channel_open_confirm(const struct channel_open_info *info,
		     struct ssh_channel *channel)
{
  assert(info->local_channel_number < info->connection->used_channels);  
  assert(info->connection->alloc_state[info->local_channel_number]
	 == CHANNEL_ALLOC_RECEIVED_OPEN);
  assert(!info->connection->channels[info->local_channel_number]);

  /* FIXME: This copying, and the ssh_connection_register_channel
   * call, could just as well be done by the CHANNEL_OPEN handler? */
  channel->send_window_size = info->send_window_size;
  channel->send_max_packet = info->send_max_packet;
  channel->remote_channel_number = info->remote_channel_number;

  ssh_connection_register_channel(info->connection,
				  info->local_channel_number,
				  channel);
  ssh_connection_activate_channel(info->connection,
				  info->local_channel_number);

  /* FIXME: Doesn't support sending extra arguments with the
   * confirmation message. */

  SSH_CONNECTION_WRITE(info->connection,
		       format_open_confirmation(channel, ""));
}

void
channel_open_deny(const struct channel_open_info *info,
		  int error, const char *msg)
{
  assert(info->local_channel_number < info->connection->used_channels);  
  assert(info->connection->alloc_state[info->local_channel_number]
	 == CHANNEL_ALLOC_RECEIVED_OPEN);
  assert(!info->connection->channels[info->local_channel_number]);

  ssh_connection_dealloc_channel(info->connection, info->local_channel_number);

  werror("Denying channel open: %z\n", msg);
  
  SSH_CONNECTION_WRITE(info->connection,
		       format_open_failure(info->remote_channel_number,
					   error, msg, ""));
}

struct channel_open_info *
parse_channel_open(struct simple_buffer *buffer)
{
  NEW(channel_open_info, info);

  if (parse_string(buffer, &info->type_length, &info->type_data)
      && parse_uint32(buffer, &info->remote_channel_number)
      && parse_uint32(buffer, &info->send_window_size)
      && parse_uint32(buffer, &info->send_max_packet))
    {
      info->type = lookup_atom(info->type_length, info->type_data);

      /* We don't support larger packets than the default,
       * SSH_MAX_PACKET. */
      if (info->send_max_packet > SSH_MAX_PACKET)
	{
	  werror("parse_channel_open: The remote end asked for really large packets.\n");
	  info->send_max_packet = SSH_MAX_PACKET;
	}

      info->local_channel_number = 0;
      return info;
    }
  else
    {
      KILL(info);
      return NULL;
    }
}

static void
handle_channel_open(struct ssh_connection *connection,
		    struct simple_buffer *buffer)
{
  struct channel_open_info *info;

  trace("handle_channel_open\n");

  info = parse_channel_open(buffer);
  if (info)
    {
      struct channel_open *open = NULL;
      
      if (connection->pending_close)
	{
	  /* We are waiting for channels to close. Don't open any new ones. */

	  SSH_CONNECTION_WRITE(connection,
		       format_open_failure(
			 info->remote_channel_number,
			 SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
			 "Waiting for channels to close.", ""));
	}
      else
	{
	  if (info->type)
	    {
	      CAST_SUBTYPE(channel_open, o,
			   ALIST_GET(connection->channel_types,
				     info->type));
	      open = o;
	    }

	  if (!open)
	    open = connection->open_fallback;

	  if (!open)
	    {
	      werror("handle_channel_open: Unknown channel type `%ps'\n",
		     info->type_length, info->type_data);
	      SSH_CONNECTION_WRITE(connection,
			   format_open_failure(
			     info->remote_channel_number,
			     SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
			     "Unknown channel type", ""));
	    }
	  else
	    {
	      int local_number
		= ssh_connection_alloc_channel(connection,
					       CHANNEL_ALLOC_RECEIVED_OPEN);

	      if (local_number < 0)
		{
		  SSH_CONNECTION_WRITE(connection,
			       format_open_failure(
				 info->remote_channel_number,
				 SSH_OPEN_RESOURCE_SHORTAGE,
				 "Channel limit exceeded.", ""));
		  return;
		}
	      info->connection = connection;
	      info->local_channel_number = local_number;

	      trace("handle_channel_open: Channel %i, window size = %i, max_packet = %i\n",
		    local_number, info->send_window_size, info->send_max_packet);

	      CHANNEL_OPEN(open, info, buffer);

	      /* Points into the packet data, no longer valid after we
		 return. */
	      info->type_data = NULL;
	    }
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid SSH_MSG_CHANNEL_OPEN message.");
}     

static void
handle_adjust_window(struct ssh_connection *connection,
		     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t size;

  if (parse_uint32(buffer, &channel_number)
      && parse_uint32(buffer, &size)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);

      if (channel
	  && !(channel->flags & CHANNEL_RECEIVED_CLOSE))
	{
	  if (! (channel->flags & (CHANNEL_SENT_CLOSE | CHANNEL_SENT_EOF)))
	    {
	      channel->send_window_size += size;

	      trace("handle_adjust_window: Channel %i, increment = %i, new window size = %i\n",
		    channel_number, size, channel->send_window_size);

	      if (channel->send_window_size && channel->send_adjust)
		channel->send_adjust(channel, size);
	    }
	}
      else
	{
	  werror("SSH_MSG_CHANNEL_WINDOW_ADJUST on nonexistant or closed "
		 "channel %i\n", channel_number);
	  SSH_CONNECTION_ERROR(connection, "Unexpected CHANNEL_WINDOW_ADJUST");
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_WINDOW_ADJUST message.");
}

/* Common processing for ordinary and "extended" data. */
static int
receive_data_common(struct ssh_channel *channel,
		    int type, uint32_t length, const uint8_t *data)
{
  if (channel->receive
      && !(channel->flags & (CHANNEL_RECEIVED_EOF
			     | CHANNEL_RECEIVED_CLOSE)))
    {
      if (channel->flags & CHANNEL_SENT_CLOSE)
	{
	  werror("Ignoring data on channel which is closing\n");
	  return 1;
	}
      else
	{
	  if (length > channel->rec_max_packet)
	    {
	      werror("Channel data larger than rec_max_packet. Extra data ignored.\n");
	      length = channel->rec_max_packet;
	    }

	  if (length > channel->rec_window_size)
	    {
	      /* Truncate data to fit window */
	      werror("Channel data overflow. Extra data ignored.\n");
	      debug("   (type = %i, data->length=%i, rec_window_size=%i).\n",
		    type, length, channel->rec_window_size);

	      length = channel->rec_window_size;
	    }

	  if (!length)
	    {
	      /* Ignore data packet */
	      return 1;
	    }
	  channel->rec_window_size -= length;
	  channel->receive(channel, type, length, data);
	}
      return 1;
    }
  else
    return 0;
}

static void
handle_channel_data(struct ssh_connection *connection,
		    struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t length;
  const uint8_t *data;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_string(buffer, &length, &data)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);

      if (channel)
	{
	  if (!receive_data_common(channel, CHANNEL_DATA,
				   length, data))
	    werror("Data on closed channel %i\n", channel_number);
	}
      else
	werror("Data on non-existant channel %i\n", channel_number);
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_DATA message.");
}

static void
handle_channel_extended_data(struct ssh_connection *connection,
			     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t type;
  uint32_t length;
  const uint8_t *data;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_uint32(buffer, &type)
      && parse_string(buffer, &length, &data)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);
      
      if (channel)
	{
	  if (type != SSH_EXTENDED_DATA_STDERR)
	    werror("Unknown type %i of extended data.\n", type);
	    
	  else if (!receive_data_common(channel, CHANNEL_STDERR_DATA,
					length, data))
	    werror("Extended data on closed channel %i\n", channel_number);
	}      
      else
	werror("Extended data on non-existant channel %i\n", channel_number);
    }
  else
    SSH_CONNECTION_ERROR(connection,
			 "Invalid CHANNEL_EXTENDED_DATA message.");
}

static void
handle_channel_eof(struct ssh_connection *connection,
		   struct simple_buffer *buffer)
{
  uint32_t channel_number;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);

      if (channel)
	{
	  if (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE))
	    {
	      werror("Receiving EOF on channel on closed channel.\n");
	      SSH_CONNECTION_ERROR(connection,
			     "Received EOF on channel on closed channel.");
	    }
	  else
	    {
	      verbose("Receiving EOF on channel %i (local %i)\n",
		      channel->remote_channel_number, channel_number);
	      
	      channel->flags |= CHANNEL_RECEIVED_EOF;
	      
	      CHANNEL_EVENT(channel, CHANNEL_EVENT_EOF);

	      /* Should we close the channel now? */
	      channel_maybe_close(channel);	      
	    }
	}
      else
	{
	  werror("EOF on non-existant channel %i\n",
		 channel_number);
	  SSH_CONNECTION_ERROR(connection, "EOF on non-existant channel");
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_EOF message");
}

static void
handle_channel_close(struct ssh_connection *connection,
		     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					channel_number,
					CHANNEL_ALLOC_ACTIVE);

      if (channel)
	{
	  verbose("Receiving CLOSE on channel %i (local %i)\n",
		  channel->remote_channel_number, channel_number);
	      
	  if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	    {
	      werror("Receiving multiple CLOSE on channel.\n");
	      SSH_CONNECTION_ERROR(connection, "Receiving multiple CLOSE on channel.");
	    }
	  else
	    {
	      channel->flags |= CHANNEL_RECEIVED_CLOSE;
	  
	      if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_NO_WAIT_FOR_EOF
				       | CHANNEL_SENT_CLOSE)))
		{
		  werror("Unexpected channel CLOSE.\n");
		}
	      CHANNEL_EVENT(channel, CHANNEL_EVENT_CLOSE);

	      if (channel->flags & CHANNEL_SENT_CLOSE)
		channel_finished(channel);
	      else
		channel_close(channel);
	    }
	}
      else
	{
	  werror("CLOSE on non-existant channel %i\n",
		 channel_number);
	  SSH_CONNECTION_ERROR(connection, "CLOSE on non-existant channel");
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_CLOSE message");
}

static void
handle_open_confirm(struct ssh_connection *connection,
		    struct simple_buffer *buffer)
{
  uint32_t local_channel_number;
  uint32_t remote_channel_number;  
  uint32_t window_size;
  uint32_t max_packet;
  
  if (parse_uint32(buffer, &local_channel_number)
      && parse_uint32(buffer, &remote_channel_number)
      && parse_uint32(buffer, &window_size)
      && parse_uint32(buffer, &max_packet)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel
	= ssh_connection_lookup_channel(connection,
					local_channel_number,
					CHANNEL_ALLOC_SENT_OPEN);

      if (channel) 
	{
	  channel->remote_channel_number = remote_channel_number;
	  channel->send_window_size = window_size;

	  /* Impose a limit, since our send buffers aren't dimensioned
	     for arbitrarily large packets. */
	  if (max_packet > SSH_MAX_DATA_SIZE)
	    max_packet = SSH_MAX_DATA_SIZE;	  
	  channel->send_max_packet = max_packet;

	  trace("handle_open_confirm: Channel %i, window size = %i, max_packet = %i\n",
		local_channel_number, window_size, max_packet);

	  ssh_connection_activate_channel(connection, local_channel_number);
	  CHANNEL_EVENT(channel, CHANNEL_EVENT_CONFIRM);
	}
      else
	{
	  werror("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel %i\n",
		 local_channel_number);
	  SSH_CONNECTION_ERROR(connection, "Unexpected CHANNEL_OPEN_CONFIRMATION.");
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_OPEN_CONFIRMATION message.");
}

static void
handle_open_failure(struct ssh_connection *connection,
		    struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t reason;

  const uint8_t *msg;
  uint32_t length;

  const uint8_t *language;
  uint32_t language_length;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_uint32(buffer, &reason)
      && parse_string(buffer, &length, &msg)
      && parse_string(buffer, &language_length, &language)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel =
	ssh_connection_lookup_channel(connection,
				      channel_number,
				      CHANNEL_ALLOC_SENT_OPEN);

      if (channel)
	{
	  /* FIXME: It would be nice to pass the message on. */
	  werror("Channel open for channel %i failed: %ps\n", channel_number, length, msg);

	  CHANNEL_EVENT(channel, CHANNEL_EVENT_DENY);
	  channel_finished(channel);
	}
      else
	werror("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE on channel %i\n",
	       channel_number);
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_OPEN_FAILURE message.");
}

static void
handle_channel_success(struct ssh_connection *connection,
		       struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct ssh_channel *channel;
      
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer)
      && (channel = ssh_connection_lookup_channel(connection,
						  channel_number,
						  CHANNEL_ALLOC_ACTIVE)))
    {
      if (!channel->pending_requests)
	werror("do_channel_success: Unexpected message. Ignoring.\n");

      else
	{
	  channel->pending_requests--;
	  CHANNEL_EVENT(channel, CHANNEL_EVENT_SUCCESS);
	}
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_SUCCESS message");
}

static void
handle_channel_failure(struct ssh_connection *connection,
		       struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct ssh_channel *channel;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer)
      && (channel = ssh_connection_lookup_channel(connection,
						  channel_number,
						  CHANNEL_ALLOC_ACTIVE)))
    {
      if (!channel->pending_requests)
	werror("do_channel_failure: Unexpected message. Ignoring.\n");

      else
	{
	  channel->pending_requests--;
	  CHANNEL_EVENT(channel, CHANNEL_EVENT_FAILURE);
	}
      
    }
  else
    SSH_CONNECTION_ERROR(connection, "Invalid CHANNEL_FAILURE message.");
}

void
channel_close(struct ssh_channel *channel)
{
  if (! (channel->flags & CHANNEL_SENT_CLOSE))
    {
      verbose("Sending CLOSE on channel %i\n", channel->remote_channel_number);

      channel->flags |= CHANNEL_SENT_CLOSE;
      
      SSH_CONNECTION_WRITE(channel->connection, format_channel_close(channel));

      if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	channel_finished(channel);
    }
}

/* Implement the close logic */
void
channel_maybe_close(struct ssh_channel *channel)
{
  trace("channel_maybe_close: flags = %xi, sources = %i, sinks = %i.\n",
	channel->flags, channel->sources, channel->sinks);

  /* We need not check channel->sources; that's done by the code that
     sends CHANNEL_EOF and sets the corresponding flag. We should
     check channel->sinks, unless CHANNEL_NO_WAIT_FOR_EOF is set. */
  if (!(channel->flags & CHANNEL_SENT_CLOSE)
      && (channel->flags & CHANNEL_SENT_EOF)
      && ((channel->flags & CHANNEL_NO_WAIT_FOR_EOF)
	  || ((channel->flags & CHANNEL_RECEIVED_EOF)
	      && !channel->sinks)))
    channel_close(channel);      
}

void
channel_eof(struct ssh_channel *channel)
{
  if (! (channel->flags &
	 (CHANNEL_SENT_EOF | CHANNEL_SENT_CLOSE | CHANNEL_RECEIVED_CLOSE)))
    {
      verbose("Sending EOF on channel %i\n", channel->remote_channel_number);

      channel->flags |= CHANNEL_SENT_EOF;
      SSH_CONNECTION_WRITE(channel->connection,
			   format_channel_eof(channel->remote_channel_number));

      channel_maybe_close(channel);
    }
}

void
init_channel(struct ssh_channel *channel,
	     void (*kill)(struct resource *),
	     void (*event)(struct ssh_channel *, enum channel_event))
{
  init_resource(&channel->super, kill);

  channel->connection = NULL;
  
  channel->flags = 0;
  channel->sources = 0;
  channel->sinks = 0;

  channel->request_types = NULL;
  channel->request_fallback = NULL;
  
  channel->receive = NULL;
  channel->send_adjust = NULL;

  channel->event = event;

  channel->pending_requests = 0;
}

/* Returns zero if message type is unimplemented */
int
channel_packet_handler(struct ssh_connection *connection,
		       uint32_t length, const uint8_t *packet)
{
  struct simple_buffer buffer;

  simple_buffer_init(&buffer, length, packet);
  unsigned msg;

  if (!parse_uint8(&buffer, &msg))
    fatal("Internal error.\n");
  
  trace("channel_packet_handler, received %T (%i)\n", msg, msg);
  debug("packet contents: %xs\n", length, packet);

  switch (msg)
    {
    default:
      return 0;
    case SSH_MSG_GLOBAL_REQUEST:
      handle_global_request(connection, &buffer);
      break;
    case SSH_MSG_REQUEST_SUCCESS:
      handle_global_success(connection, &buffer);
      break;
    case SSH_MSG_REQUEST_FAILURE:
      handle_global_failure(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN:
      handle_channel_open(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      handle_open_confirm(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
      handle_open_failure(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
      handle_adjust_window(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_DATA:
      handle_channel_data(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_EXTENDED_DATA:
      handle_channel_extended_data(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_EOF:
      handle_channel_eof(connection, &buffer);
      break;
    case SSH_MSG_CHANNEL_CLOSE:
      handle_channel_close(connection, &buffer);       
      break;
    case SSH_MSG_CHANNEL_REQUEST:
      handle_channel_request(connection, &buffer); 
      break;
    case SSH_MSG_CHANNEL_SUCCESS:
      handle_channel_success(connection, &buffer); 
      break;
    case SSH_MSG_CHANNEL_FAILURE:
      handle_channel_failure(connection, &buffer); 
      break;
    }
  return 1;
}

void
channel_transmit_data(struct ssh_channel *channel,
		      uint32_t length, const uint8_t *data)
{
  assert(length <= channel->send_window_size);
  assert(length <= channel->send_max_packet);
  channel->send_window_size -= length;

  SSH_CONNECTION_WRITE(channel->connection,
		       format_channel_data(channel->remote_channel_number,
					   length, data));
}

void
channel_transmit_extended(struct ssh_channel *channel,
			  uint32_t type,
			  uint32_t length, const uint8_t *data)
{
  assert(length <= channel->send_window_size);
  assert(length <= channel->send_max_packet);
  channel->send_window_size -= length;

  SSH_CONNECTION_WRITE(channel->connection,
		       format_channel_extended_data(
			 channel->remote_channel_number,
			 type, length, data));
}

int
channel_open_new_v(struct ssh_connection *connection,
		   struct ssh_channel *channel,
		   uint32_t type_length, const uint8_t *type,
		   const char *format, va_list args)
{
  struct lsh_string *request;
  uint32_t l1, l2;
  va_list args_copy;

  int index
    = ssh_connection_alloc_channel(connection, CHANNEL_ALLOC_SENT_OPEN);
  if (index < 0)
    {
      /* We have run out of channel numbers. */
      werror("channel_open_new: ssh_connection_alloc_channel failed\n");
      return 0;
    }

  ssh_connection_register_channel(connection, index, channel);
  
  check_rec_max_packet(channel);
  
#define OPEN_FORMAT "%c%s%i%i%i"
#define OPEN_ARGS SSH_MSG_CHANNEL_OPEN, type_length, type, \
  channel->local_channel_number, \
  channel->rec_window_size, channel->rec_max_packet

  va_copy(args_copy, args);

  l1 = ssh_format_length(OPEN_FORMAT, OPEN_ARGS);
  
  l2 = ssh_vformat_length(format, args);

  request = lsh_string_alloc(l1 + l2);

  ssh_format_write(OPEN_FORMAT, request, 0, OPEN_ARGS);

  ssh_vformat_write(format, request, l1, args_copy);
  va_end(args_copy);

#undef OPEN_FORMAT
#undef OPEN_ARGS
  
  SSH_CONNECTION_WRITE(connection, request);
  
  return 1;
}

int
channel_open_new_type(struct ssh_connection *connection,
		      struct ssh_channel *channel,
		      uint32_t type_length, const uint8_t *type,
		      const char *format, ...)
{
  va_list args;
  int res;
  
  va_start(args, format);
  res = channel_open_new_v(connection, channel,
			   type_length, type,
			   format, args);
  va_end(args);
  return res;
}

int
channel_send_request(struct ssh_channel *channel,
		     uint32_t type_length, const uint8_t *type,
		     int want_reply,
		     const char *format, ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;

  if (channel->flags & CHANNEL_SENT_CLOSE)
    return 0;

#define REQUEST_FORMAT "%c%i%s%c"
#define REQUEST_ARGS SSH_MSG_CHANNEL_REQUEST, channel->remote_channel_number, \
    type_length, type, want_reply

  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, packet, 0, REQUEST_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

#undef REQUEST_FORMAT
#undef REQUEST_ARGS

  SSH_CONNECTION_WRITE(channel->connection, packet);

  if (want_reply)
    channel->pending_requests++;

  return 1;
}

void
channel_send_global_request(struct ssh_connection *connection, int type,
			    struct command_context *ctx,
			    const char *format, ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;
  uint8_t want_reply;

#define REQUEST_FORMAT "%c%a%c"
#define REQUEST_ARGS SSH_MSG_GLOBAL_REQUEST, type, want_reply

  want_reply = (ctx != NULL);

  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, packet, 0, REQUEST_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

#undef REQUEST_FORMAT
#undef REQUEST_ARGS
  
  SSH_CONNECTION_WRITE(connection, packet);
  if (want_reply)
    {
      assert(ctx);
      object_queue_add_tail(&connection->pending_global_requests,
			    &ctx->super);
    }      
}

/* In principle, these belong to connection.c, but it needs the
   definition of ssh_channel. */
void
ssh_connection_register_channel(struct ssh_connection *connection,
				uint32_t local_channel_number,
				struct ssh_channel *channel)
{
  assert(local_channel_number < connection->used_channels);
  assert(connection->alloc_state[local_channel_number] != CHANNEL_FREE);
  assert(!connection->channels[local_channel_number]);

  trace("ssh_connection_register_channel: local_channel_number: %i.\n",
	local_channel_number);

  connection->channels[local_channel_number] = channel;
  channel->connection = connection;
  /* FIXME: If we keep the local_channel_number attribute,
     we can probably use it in more places. */
  channel->local_channel_number = local_channel_number;
  remember_resource(connection->resources, &channel->super);  
}

/* FIXME: Does not affect channels that are in the opening
   handshake. */
static void
send_stop(struct ssh_channel *channel)
{
  CHANNEL_EVENT(channel, CHANNEL_EVENT_STOP);
}

void
ssh_connection_stop_channels(struct ssh_connection *connection)
{
  ssh_connection_foreach(connection, send_stop);
}

static void
send_start(struct ssh_channel *channel)
{
  CHANNEL_EVENT(channel, CHANNEL_EVENT_START);
}

void
ssh_connection_start_channels(struct ssh_connection *connection)
{
  ssh_connection_foreach(connection, send_start);
}
