/* channel.c
 *
 * $Id$
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

#include "channel.h"

#include "format.h"
#include "io.h"
#include "read_data.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#define GABA_DEFINE
#include "channel.h.x"
#undef GABA_DEFINE

#include "channel.c.x"

struct exception *make_channel_open_exception(UINT32 error_code, char *msg)
{
  NEW(channel_open_exception, self);

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
  
  self->super.type = EXC_CHANNEL_OPEN;
  self->super.msg = msg ? msg : msgs[error_code];
  self->error_code = error_code;

  return &self->super;
}

/* GABA:
   (class
     (name connection_service)
     (super command)
     (vars
       ; Supported global requests 
       (global_requests object alist)

       (channel_types object alist) ))

       ; Initialize connection (for instance, request channels to be 
       ; opened or services to be forwarded).

       ; (start object connection_startup)))
*/

/* ;; GABA:
   (class
     (name global_request_handler)
     (super packet_handler)
     (vars
       (global_requests object alist)))
*/

/* ;; GABA:
   (class
     (name channel_open_handler)
     (super packet_handler)
     (vars
       (channel_types object alist)))
*/

/* ;; GABA:
   (class
     (name channel_open_response)
     (super channel_open_callback)
     (vars
       (remote_channel_number simple UINT32)
       (window_size simple UINT32)
       (max_packet simple UINT32)))
*/

struct lsh_string *format_global_failure(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_FAILURE);
}

struct lsh_string *format_global_success(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_SUCCESS);
}

struct lsh_string *format_open_confirmation(struct ssh_channel *channel,
					    UINT32 channel_number,
					    const char *format, ...)
{
  va_list args;
  UINT32 l1, l2;
  struct lsh_string *packet;

#define CONFIRM_FORMAT "%c%i%i%i%i"
#define CONFIRM_ARGS \
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION, channel->channel_number, \
  channel_number, channel->rec_window_size, channel->rec_max_packet
    
  l1 = ssh_format_length(CONFIRM_FORMAT, CONFIRM_ARGS);

  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(CONFIRM_FORMAT, l1, packet->data, CONFIRM_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, l2, packet->data+l1, args);
  va_end(args);

  return packet;
#undef CONFIRM_FORMAT
#undef CONFIRM_ARGS
}

struct lsh_string *format_open_failure(UINT32 channel, UINT32 reason,
				       const char *msg, const char *language)
{
  return ssh_format("%c%i%i%z%z", SSH_MSG_CHANNEL_OPEN_FAILURE,
		    channel, reason, msg, language);
}

struct lsh_string *format_channel_success(UINT32 channel)
{
  return ssh_format("%c%i", SSH_MSG_CHANNEL_SUCCESS, channel);
}

struct lsh_string *format_channel_failure(UINT32 channel)
{
  return ssh_format("%c%i", SSH_MSG_CHANNEL_FAILURE, channel);
}

struct lsh_string *prepare_window_adjust(struct ssh_channel *channel,
					 UINT32 add)
{
  channel->rec_window_size += add;
  
  return ssh_format("%c%i%i",
		    SSH_MSG_CHANNEL_WINDOW_ADJUST,
		    channel->channel_number, add);
}

/* ;; GABA:
   (class
     (name channel_exception)
     (super exception)
     (vars
       (channel object ssh_channel)
       (pending_close . int)))
*/

/* GABA:
   (class
     (name exc_finish_channel_handler)
     (super exception_handler)
     (vars
       (table object channel_table)
       ; Local channel number 
       (channel_number . UINT32)))
*/

static void do_exc_finish_channel_handler(struct exception_handler *s,
					  const struct exception *e)
{
  CAST(exc_finish_channel_handler, self, s);

  switch (e->type)
    {
    case EXC_FINISH_PENDING:
      self->table->pending_close = 1;

      if (!self->table->next_channel)
	EXCEPTION_RAISE(self->super.parent, &finish_read_exception);
      break;
      
    case EXC_FINISH_CHANNEL:
      /* NOTE: This type of exception must be handled only once.
       * Perhaps we must add a liveness flag in the ssh_channel struct
       * to avoid deallocating dead channels? */
      {
	struct ssh_channel *channel
	  = self->table->channels[self->channel_number];

	assert(channel);
	assert(channel->resources->super.alive);

	if (channel->close)
	  CHANNEL_CLOSE(channel);

	KILL_RESOURCE_LIST(channel->resources);
	
	dealloc_channel(self->table, self->channel_number);

	if (self->table->pending_close && !self->table->next_channel)
	  {
	    /* FIXME: Send a SSH_DISCONNECT_BY_APPLICATION message? */
	    EXCEPTION_RAISE(self->super.parent, &finish_read_exception);
	  }
      }
      break;
    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }
}

static struct exception_handler *
make_exc_finish_channel_handler(struct channel_table *table,
				UINT32 channel_number,
				struct exception_handler *e,
				const char *context)
{
  NEW(exc_finish_channel_handler, self);
  self->super.parent = e;
  self->super.raise = do_exc_finish_channel_handler;
  self->super.context = context;

  self->table = table;
  self->channel_number = channel_number;
  
  return &self->super;
}
				

/* Channel objects */

#define INITIAL_CHANNELS 32
/* Arbitrary limit */
#define MAX_CHANNELS (1L<<17)

struct channel_table *make_channel_table(void)
{
  NEW(channel_table, table);

  table->channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				      * INITIAL_CHANNELS);
  table->in_use = lsh_space_alloc(INITIAL_CHANNELS);
  
  table->allocated_channels = INITIAL_CHANNELS;
  table->next_channel = 0;
  table->used_channels = 0;
  table->max_channels = MAX_CHANNELS;

  table->pending_close = 0;

  table->global_requests = make_alist(0, -1);
  table->channel_types = make_alist(0, -1);
  
  object_queue_init(&table->local_ports);
  object_queue_init(&table->remote_ports);
  
  object_queue_init(&table->active_global_requests);
  object_queue_init(&table->pending_global_requests);
  
  return table;
};

/* Returns -1 if allocation fails */
/* NOTE: This function returns locally chosen channel numbers, which
 * are always small integers. So there's no problem fitting them in
 * a signed int. */
int alloc_channel(struct channel_table *table)
{
  UINT32 i;
  
  for(i = table->next_channel; i < table->used_channels; i++)
    {
      if (!table->in_use[i])
	{
	  assert(!table->channels[i]);
	  table->in_use[i] = 1;
	  table->next_channel = i+1;
	  return i;
	}
    }
  if (i == table->max_channels)
    return -1;

  if (i == table->allocated_channels) 
    {
      int new_size = table->allocated_channels * 2;
      struct ssh_channel **new_channels;
      UINT8 *new_in_use;

      new_channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				     * new_size);
      memcpy(new_channels, table->channels,
	     sizeof(struct ssh_channel *) * table->used_channels);
      lsh_space_free(table->channels);
      table->channels = new_channels;

      new_in_use = lsh_space_alloc(new_size);
      memcpy(new_in_use, table->in_use, table->used_channels);
      lsh_space_free(table->in_use);
      table->in_use = new_in_use;

      table->allocated_channels = new_size;
    }

  table->next_channel = table->used_channels = i+1;

  table->in_use[i] = 1;
  return i;
}

void dealloc_channel(struct channel_table *table, int i)
{
  assert(i >= 0);
  assert( (unsigned) i < table->used_channels);
  
  table->channels[i] = NULL;
  table->in_use[i] = 0;
  
  if ( (unsigned) i < table->next_channel)
    table->next_channel = i;
}

void
register_channel(struct ssh_connection *connection,
		 UINT32 local_channel_number,
		 struct ssh_channel *channel)
{
  struct channel_table *table = connection->table;
  
  assert(table->in_use[local_channel_number]);
  assert(!table->channels[local_channel_number]);
  
  table->channels[local_channel_number] = channel;

  /* FIXME: Is this the right place to install this exception handler? */
  channel->e = make_exc_finish_channel_handler(table,
					       local_channel_number,
					       connection->e,
					       HANDLER_CONTEXT);

  REMEMBER_RESOURCE(connection->resources, &channel->resources->super);
}

struct ssh_channel *lookup_channel(struct channel_table *table, UINT32 i)
{
  return (i < table->used_channels)
    ? table->channels[i] : NULL;
}

/* FIXME: It seems suboptimal to send a window adjust message for *every* write that we do.
 * A better scheme might be as follows:
 *
 * Delay window adjust messages, keeping track of both the locally
 * maintained window size, which is updated after each write, and the
 * size that has been reported to the remote end. When the difference
 * between these two values gets large enough (say, larger than one
 * half or one third of the maximum window size), we send a
 * window_adjust message to sync them. */
static void adjust_rec_window(struct flow_controlled *f, UINT32 written)
{
  CAST_SUBTYPE(ssh_channel, channel, f);

  A_WRITE(channel->write,
	  prepare_window_adjust(channel, written));
}

void channel_start_receive(struct ssh_channel *channel)
{
  A_WRITE(channel->write,
	  prepare_window_adjust
	  (channel, channel->max_window - channel->rec_window_size));
}


/* Ugly macros to make it a little simpler to free the input packet at
 * the right time. */

#define RETURN goto foo_finish
#define END(s) do { foo_finish: \
                    lsh_string_free((s)); \
                    return; } while(0)


/* Channel related messages */

/* GABA:
   (class
     (name global_request_status)
     (vars
       ; -1 for still active requests,
       ; 0 for failure,
       ; 1 for success
       (status . int)))
*/

static struct global_request_status *make_global_request_status(void)
{
  NEW(global_request_status, self);
  self->status = -1;

  return self;
}

/* FIXME: Split into a continuation and an exception handler */
/* GABA:
   (class
     (name global_request_response)
     (super global_request_callback)
     (vars
       (active object global_request_status)))
*/

static void
do_global_request_response(struct global_request_callback *c,
			   int success)
{
  CAST(global_request_response, self, c);
  struct object_queue *q = &self->super.connection->table->active_global_requests;

  assert( self->active->status == -1);
  assert( (success == 0) || (success == 1) );
  assert( !object_queue_is_empty(q));
	  
  self->active->status = success;

  for (;;)
    {
      CAST(global_request_status, n, object_queue_peek_head(q));
      if (!n || (n->status < 0))
	break;

      object_queue_remove_head(q);

      /* FIXME: Perhaps install some exception handler that cancels
       * the queue as soon as a write failes. */
      C_WRITE(self->super.connection,
	      (n->status
	       ? format_global_success()
	       : format_global_failure()));
    }
}

static struct global_request_callback *
make_global_request_response(struct ssh_connection *connection,
			     struct global_request_status *active)
{
  NEW(global_request_response, self);

  self->super.connection = connection;
  self->super.response = do_global_request_response;

  self->active = active;

  return &self->super;
}
     
static void do_global_request(struct packet_handler *s UNUSED,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  /* CAST(global_request_handler, closure, c); */

  struct simple_buffer buffer;
  unsigned msg_number;
  int name;
  int want_reply;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_GLOBAL_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_boolean(&buffer, &want_reply))
    {
      struct global_request *req;
      struct global_request_callback *c = NULL;
      
      if (!name || !(req = ALIST_GET(connection->table->global_requests,
				     name)))
	{
	  lsh_string_free(packet);

	  C_WRITE(connection, format_global_failure());
	  return;
	}
      else
	{
	  if (want_reply)
	    {
	      struct global_request_status *a = make_global_request_status();
	      
	      object_queue_add_tail(&connection->table->active_global_requests,
				    &a->super);
	      
	      c = make_global_request_response(connection, a);
	    }
	  GLOBAL_REQUEST(req, connection, &buffer, c);
	}
    }
  else
    {
      PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_GLOBAL_REQUEST message.");
    }
  lsh_string_free(packet);
}

static void
do_global_request_success(struct packet_handler *s UNUSED,
			  struct ssh_connection *connection,
			  struct lsh_string *packet)
{
  if (packet->length != 1)
    {
      PROTOCOL_ERROR(connection->e, "Invalid GLOBAL_REQUEST_SUCCESS message.");
      RETURN;
    }

  assert(packet->data[0] == SSH_MSG_REQUEST_SUCCESS);

  if (object_queue_is_empty(&connection->table->pending_global_requests))
    {
      werror("do_global_request_success: Unexpected message, ignoring.\n");
      return;
    }
  {
    CAST_SUBTYPE(command_context, ctx,
		 object_queue_remove_head(&connection->table->pending_global_requests));
    COMMAND_RETURN(ctx->c, connection);
  }
  END(packet);
}

struct exception global_request_exception =
STATIC_EXCEPTION(EXC_GLOBAL_REQUEST, "Global request failed");

static void
do_global_request_failure(struct packet_handler *s UNUSED,
			  struct ssh_connection *connection,
			  struct lsh_string *packet)
{
  if (packet->length != 1)
    {
      PROTOCOL_ERROR(connection->e, "Invalid GLOBAL_REQUEST_FAILURE message.");
      RETURN;
    }

  assert(packet->data[0] == SSH_MSG_REQUEST_FAILURE);

  if (object_queue_is_empty(&connection->table->pending_global_requests))
    {
      werror("do_global_request_failure: Unexpected message, ignoring.\n");
    }
  else
    {
      CAST_SUBTYPE(command_context, ctx,
		   object_queue_remove_head(&connection->table->pending_global_requests));
      EXCEPTION_RAISE(ctx->e, &global_request_exception);
    }
  END(packet);
}


/* GABA:
   (class
     (name channel_open_continuation)
     (super command_continuation)
     (vars
       (connection object ssh_connection)
       (local_channel_number . UINT32)
       (remote_channel_number . UINT32)
       (window_size . UINT32)
       (max_packet . UINT32)))
*/

static void
do_channel_open_continue(struct command_continuation *c,
			 struct lsh_object *value)
{
  CAST(channel_open_continuation, self, c);
  CAST_SUBTYPE(ssh_channel, channel, value);

  assert(channel);

  /* FIXME: This copying could just as well be done by the
   * CHANNEL_OPEN handler? Then we can remove the corresponding fields
   * from the closure as well. */
  channel->send_window_size = self->window_size;
  channel->send_max_packet = self->max_packet;
  channel->channel_number = self->remote_channel_number;

  /* FIXME: Is the channel->write field really needed? */
  channel->write = self->connection->write;

  register_channel(self->connection,
		   self->local_channel_number, channel);

  /* FIXME: Doesn't support sending extra arguments with the
   * confirmation message. */

  C_WRITE(self->connection,
	  format_open_confirmation(channel, self->local_channel_number, ""));
}

static struct command_continuation *
make_channel_open_continuation(struct ssh_connection *connection,
			       UINT32 local_channel_number,
			       UINT32 remote_channel_number,
			       UINT32 window_size,
			       UINT32 max_packet)
{
  NEW(channel_open_continuation, self);

  self->super.c = do_channel_open_continue;
  self->connection = connection;
  self->local_channel_number = local_channel_number;
  self->remote_channel_number = remote_channel_number;
  self->window_size = window_size;
  self->max_packet = max_packet;

  return &self->super;
}
			       
/* GABA:
   (class
     (name exc_channel_open_handler)
     (super exception_handler)
     (vars
       (connection object ssh_connection)
       (local_channel_number . UINT32)
       (remote_channel_number . UINT32)))
*/

static void do_exc_channel_open_handler(struct exception_handler *s,
					const struct exception *e)
{
  CAST(exc_channel_open_handler, self, s);

  switch (e->type)
    {
    case EXC_CHANNEL_OPEN:
      {
	CAST_SUBTYPE(channel_open_exception, exc, e);
	struct channel_table *table = self->connection->table;
	
	assert(table->in_use[self->local_channel_number]);
	assert(!table->channels[self->local_channel_number]);

	dealloc_channel(table, self->local_channel_number);
	
        C_WRITE(self->connection,
		format_open_failure(self->remote_channel_number,
				    exc->error_code, e->msg, ""));
	break;
      }
    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }      
}

static struct exception_handler *
make_exc_channel_open_handler(struct ssh_connection *connection,
			      UINT32 local_channel_number,
			      UINT32 remote_channel_number,
			      struct exception_handler *parent)
{
  NEW(exc_channel_open_handler, self);
  self->super.parent = parent;
  self->super.raise = do_exc_channel_open_handler;
  self->connection = connection;
  self->local_channel_number = local_channel_number;
  self->remote_channel_number = remote_channel_number;

  return &self->super;
}

static void do_channel_open(struct packet_handler *c UNUSED,
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  /* CAST(channel_open_handler, closure, c); */

  struct simple_buffer buffer;
  unsigned msg_number;
  int type;
  UINT32 remote_channel_number;
  UINT32 window_size;
  UINT32 max_packet;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_OPEN)
      && parse_atom(&buffer, &type)
      && parse_uint32(&buffer, &remote_channel_number)
      && parse_uint32(&buffer, &window_size)
      && parse_uint32(&buffer, &max_packet))
    {
      struct channel_open *open;

      /* NOTE: We can't free the packet yet, as the buffer is passed
       * to the CHANNEL_OPEN method later. */

      if (connection->table->pending_close)
	{
	  /* We are waiting for channels to close. Don't open any new ones. */

	  C_WRITE(connection,
		  format_open_failure(remote_channel_number,
				      SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
				      "Waiting for channels to close.", ""));
	}
      else if (!type || !(open = ALIST_GET(connection->table->channel_types,
				      type)))
	{
	  C_WRITE(connection,
		  format_open_failure(remote_channel_number,
				      SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
				      "Unknown channel type", ""));
	}
      else
	{
      	  int local_number = alloc_channel(connection->table);

	  if (local_number < 0)
	    C_WRITE(connection,
		    format_open_failure(remote_channel_number,
					SSH_OPEN_RESOURCE_SHORTAGE,
					"Unknown channel type", ""));

	  
	  
	  CHANNEL_OPEN(open, connection, &buffer,
		       make_channel_open_continuation(connection,
						      local_number,
						      remote_channel_number,
						      window_size,
						      max_packet),
		       make_exc_channel_open_handler(connection,
						     local_number,
						     remote_channel_number,
						     connection->e));
	}
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_CHANNEL_OPEN message.");

  lsh_string_free(packet);
}     

static void
do_channel_request(struct packet_handler *closure UNUSED,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  int type;
  int want_reply;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_REQUEST)
      && parse_uint32(&buffer, &channel_number)
      && parse_atom(&buffer, &type)
      && parse_boolean(&buffer, &want_reply))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      /* NOTE: We can't free packet yet, because it is not yet fully
       * parsed. There may be some more arguments, which are parsed by
       * the CHANNEL_REQUEST method below. */

      if (channel)
	{
	  struct channel_request *req;

	  if (type && channel->request_types 
	      && ( (req = ALIST_GET(channel->request_types, type)) ))
	    CHANNEL_REQUEST(req, channel, connection, want_reply, &buffer);
	  else
	    {
	      if (want_reply)
		C_WRITE(connection,
			format_channel_failure(channel->channel_number));
	    }
	}
      else
	{
	  werror("SSH_MSG_CHANNEL_REQUEST on nonexistant channel %i\n",
		 channel_number);
	}
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_CHANNEL_REQUEST message.");
  
  lsh_string_free(packet);
}
      
static void
do_window_adjust(struct packet_handler *closure UNUSED,
		 struct ssh_connection *connection,
		 struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  UINT32 size;

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_WINDOW_ADJUST)
      && parse_uint32(&buffer, &channel_number)
      && parse_uint32(&buffer, &size)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel
	  && !(channel->flags & (CHANNEL_RECEIVED_EOF
				 | CHANNEL_RECEIVED_CLOSE)))
	{
	  if (! (channel->flags & CHANNEL_SENT_CLOSE))
	    {
	      channel->send_window_size += size;
	      if (channel->send_window_size && channel->send)
		CHANNEL_SEND(channel, connection);
	    }
	}
      else
	{
	  /* FIXME: What to do now? Should unknown channel numbers be
	   * ignored silently? */
	  werror("SSH_MSG_CHANNEL_WINDOW_ADJUST on nonexistant or closed "
		 "channel %i\n", channel_number);
	  PROTOCOL_ERROR(connection->e, "Unexpected CHANNEL_WINDOW_ADJUST");
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_WINDOW_ADJUST message.");
    }
}

static void
do_channel_data(struct packet_handler *closure UNUSED,
		struct ssh_connection *connection,
		struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  struct lsh_string *data;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_DATA)
      && parse_uint32(&buffer, &channel_number)
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->receive
	  && !(channel->flags & (CHANNEL_RECEIVED_EOF
				 | CHANNEL_RECEIVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      lsh_string_free(data);
	      werror("Ignoring data on channel which is closing\n");
	      return;
	    }
	  else
	    {
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel data overflow. Extra data ignored.\n"); 
		  data->length = channel->rec_window_size;
		}

	      if (!data->length)
		{
		  /* Ignore data packet */
		  lsh_string_free(data);
		  return;
		}
	      channel->rec_window_size -= data->length;

	      CHANNEL_RECEIVE(channel, CHANNEL_DATA, data);
	    }
	}
      else
	{
	  werror("Data on closed or non-existant channel %i\n",
		 channel_number);
	  lsh_string_free(data);
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_DATA message.");
    }
}

static void
do_channel_extended_data(struct packet_handler *closure UNUSED,
			 struct ssh_connection *connection,
			 struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  UINT32 type;
  struct lsh_string *data;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_EXTENDED_DATA)
      && parse_uint32(&buffer, &channel_number)
      && parse_uint32(&buffer, &type)
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->receive
	  && !(channel->flags & (CHANNEL_RECEIVED_EOF
				 | CHANNEL_RECEIVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      lsh_string_free(data);
	      werror("Ignoring extended data on channel which is closing\n");
	      return;
	    }
	  else
	    {
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel extended data overflow. "
			 "Extra data ignored.\n");
		  data->length = channel->rec_window_size;
		}
	      
	      if (!data->length)
		{
		  /* Ignore data packet */
		  lsh_string_free(data);
		  return;
		}

	      channel->rec_window_size -= data->length;

	      switch(type)
		{
		case SSH_EXTENDED_DATA_STDERR:
		  CHANNEL_RECEIVE(channel, CHANNEL_STDERR_DATA, data);
		  break;
		default:
		  werror("Unknown type %i of extended data.\n",
			 type);
		  lsh_string_free(data);
		}
	    }
	}
      else
	{
	  werror("Extended data on closed or non-existant channel %i\n",
		 channel_number);
	  lsh_string_free(data);
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_EXTENDED_DATA message.");
    }
}

static void
do_channel_eof(struct packet_handler *closure UNUSED,
	       struct ssh_connection *connection,
	       struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_EOF)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet);

      if (channel)
	{
	  if (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE))
	    {
	      werror("Receiving EOF on channel on closed channel.\n");
	      PROTOCOL_ERROR(connection->e,
			     "Received EOF on channel on closed channel.");
	    }
	  else
	    {
	      channel->flags |= CHANNEL_RECEIVED_EOF;
	      
	      if (channel->eof)
		CHANNEL_EOF(channel);
	      else
		/* FIXME: What is a reasonable default behaviour?
		 * Closing the channel may be the right thing to do. */
		channel_close(channel);
	    }
	}
      else
	{
	  werror("EOF on non-existant channel %i\n",
		 channel_number);
	  PROTOCOL_ERROR(connection->e, "EOF on non-existant channel");
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_EOF message");
    }
}

static void
do_channel_close(struct packet_handler *closure UNUSED,
		 struct ssh_connection *connection,
		 struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_CLOSE)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	    {
	      werror("Receiving multiple CLOSE on channel.\n");
	      PROTOCOL_ERROR(connection->e, "Receiving multiple CLOSE on channel.");
	    }
	  else
	    {
	      channel->flags |= CHANNEL_RECEIVED_CLOSE;
	  
	      if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_SENT_EOF
				       | CHANNEL_SENT_CLOSE)))
		{
		  werror("Unexpected channel CLOSE.\n");
		}

	      if (! (channel->flags & (CHANNEL_RECEIVED_EOF))
		  && channel->eof)
		CHANNEL_EOF(channel);

	      if (channel->flags & (CHANNEL_SENT_CLOSE))
		{
		  static const struct exception finish_exception
		    = STATIC_EXCEPTION(EXC_FINISH_CHANNEL, "Received CLOSE message.");
	      
		  EXCEPTION_RAISE(channel->e,
				  &finish_exception);
		}
	      else
		channel_close(channel);
	    }
	}
      else
	{
	  werror("CLOSE on non-existant channel %i\n",
		 channel_number);
	  PROTOCOL_ERROR(connection->e, "CLOSE on non-existant channel");
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_CLOSE message");
    }
}

static void
do_channel_open_confirm(struct packet_handler *closure UNUSED,
			struct ssh_connection *connection,
			struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 local_channel_number;
  UINT32 remote_channel_number;  
  UINT32 window_size;
  UINT32 max_packet;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
      && parse_uint32(&buffer, &local_channel_number)
      && parse_uint32(&buffer, &remote_channel_number)
      && parse_uint32(&buffer, &window_size)
      && parse_uint32(&buffer, &max_packet)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   local_channel_number);

      lsh_string_free(packet);

      if (channel && channel->open_continuation)
	{
	  struct command_continuation *c = channel->open_continuation;
	  channel->open_continuation = NULL;
	  
	  channel->channel_number = remote_channel_number;
	  channel->send_window_size = window_size;
	  channel->send_max_packet = max_packet;

	  COMMAND_RETURN(c, channel);
	}
      else
	{
	  werror("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel %i\n",
		 local_channel_number);
	  PROTOCOL_ERROR(connection->e, "Unexpected CHANNEL_OPEN_CONFIRMATION.");
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_OPEN_CONFIRMATION message.");
    }
}

static void
do_channel_open_failure(struct packet_handler *closure UNUSED,
			struct ssh_connection *connection,
			struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  UINT32 reason;

  UINT8 *msg;
  UINT32 length;

  UINT8 *language;
  UINT32 language_length;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_OPEN_FAILURE)
      && parse_uint32(&buffer, &channel_number)
      && parse_uint32(&buffer, &reason)
      && parse_string(&buffer, &length, &msg)
      && parse_string(&buffer, &language_length, &language)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(connection->table,
						   channel_number);

      lsh_string_free(packet); 

      if (channel && channel->open_continuation)
	{
	  static const struct exception finish_exception
	    = STATIC_EXCEPTION(EXC_FINISH_CHANNEL, "CHANNEL_OPEN failed.");

	  /* FIXME: It would be nice to pass the message on. */
	  EXCEPTION_RAISE(channel->e,
			  make_channel_open_exception(reason, "Refused by server"));
	  EXCEPTION_RAISE(channel->e, &finish_exception);
	}
      else
	werror("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE on channel %i\n",
	       channel_number);
    }
  else
    {
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_OPEN_FAILURE message.");
      lsh_string_free(packet);
    }
}

static void
do_channel_success(struct packet_handler *closure UNUSED,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  struct ssh_channel *channel;
      
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_SUCCESS)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer)
      && (channel = lookup_channel(connection->table, channel_number)))
    {
      lsh_string_free(packet);

      if (object_queue_is_empty(&channel->pending_requests))
	{
	  werror("do_channel_success: Unexpected message. Ignoring.\n");
	}
      else
	{
	  CAST_SUBTYPE(command_context, ctx,
		       object_queue_remove_head(&channel->pending_requests));
	  
	  COMMAND_RETURN(ctx->c, channel);
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_SUCCESS message");
    }
}

static struct exception channel_request_exception =
STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Channel request failed");

static void
do_channel_failure(struct packet_handler *closure UNUSED,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 channel_number;
  struct ssh_channel *channel;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_FAILURE)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer)
      && (channel = lookup_channel(connection->table, channel_number)))
    {
      lsh_string_free(packet);
      
      if (object_queue_is_empty(&channel->pending_requests))
	{
	  werror("do_channel_failure: No handler. Ignoring.\n");
	}
      else
	{
	  CAST_SUBTYPE(command_context, ctx,
		       object_queue_remove_head(&channel->pending_requests));
	  
	  EXCEPTION_RAISE(ctx->e, &channel_request_exception);
	}
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_FAILURE message.");
    }
}

static void
do_connection_service(struct command *s UNUSED,
		      struct lsh_object *x,
		      struct command_continuation *c,
		      struct exception_handler *e UNUSED)
{
  CAST(ssh_connection, connection, x);

  struct channel_table *table;
  
  NEW(packet_handler, globals);
  NEW(packet_handler, open);
  NEW(packet_handler, request);

  NEW(packet_handler, adjust);
  NEW(packet_handler, data);
  NEW(packet_handler, extended);

  NEW(packet_handler, eof);
  NEW(packet_handler, close);

  NEW(packet_handler, open_confirm);
  NEW(packet_handler, open_failure);

  NEW(packet_handler, channel_success);
  NEW(packet_handler, channel_failure);

  NEW(packet_handler, global_success);
  NEW(packet_handler, global_failure);
  
  debug("channel.c: do_connection_service()\n");
  
  table = make_channel_table();
  
  connection->table = table;
  
  globals->handler = do_global_request;
  /* globals->global_requests = self->global_requests; */
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = globals;
    
  open->handler = do_channel_open;
  /* open->channel_types = self->channel_types; */
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = open;
  
  request->handler = do_channel_request;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = request;
  
  adjust->handler = do_window_adjust;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = adjust;

  data->handler = do_channel_data;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = data;

  extended->handler = do_channel_extended_data;
  connection->dispatch[SSH_MSG_CHANNEL_EXTENDED_DATA] = extended;

  eof->handler = do_channel_eof;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = eof;

  close->handler = do_channel_close;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = close;

  open_confirm->handler = do_channel_open_confirm;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = open_confirm;

  open_failure->handler = do_channel_open_failure;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = open_failure;
  
  channel_success->handler = do_channel_success;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = channel_success;

  channel_failure->handler = do_channel_failure;
  connection->dispatch[SSH_MSG_CHANNEL_FAILURE] = channel_failure;

  global_success->handler = do_global_request_success;
  connection->dispatch[SSH_MSG_REQUEST_SUCCESS] = global_success;

  global_failure->handler = do_global_request_failure;
  connection->dispatch[SSH_MSG_REQUEST_FAILURE] = global_failure;
  
  COMMAND_RETURN(c, connection);
}


struct command
connection_service = STATIC_COMMAND(do_connection_service);

struct lsh_string *format_channel_close(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_CLOSE,
		    channel->channel_number);
}

void channel_close(struct ssh_channel *channel)
{
  static const struct exception finish_exception =
    STATIC_EXCEPTION(EXC_FINISH_CHANNEL, "Closing channel");

  if (! (channel->flags & CHANNEL_SENT_CLOSE))
    {
      channel->flags |= CHANNEL_SENT_CLOSE;
      
      A_WRITE(channel->write, format_channel_close(channel) );

      if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	EXCEPTION_RAISE(channel->e, &finish_exception);
    }
}

struct lsh_string *format_channel_eof(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_EOF,
		    channel->channel_number);
}

void channel_eof(struct ssh_channel *channel)
{
  if (! (channel->flags &
	 (CHANNEL_SENT_EOF | CHANNEL_SENT_CLOSE | CHANNEL_RECEIVED_CLOSE)))
    {
      channel->flags |= CHANNEL_SENT_EOF;
      A_WRITE(channel->write, format_channel_eof(channel) );

      if ( (channel->flags & CHANNEL_CLOSE_AT_EOF)
	   && (channel->flags & CHANNEL_RECEIVED_EOF))
	{
	  /* Initiate close */
	  channel_close(channel);
	}
    }
}

void init_channel(struct ssh_channel *channel)
{
  /* channel->super.handler = do_read_channel; */
  channel->write = NULL;
  channel->super.report = adjust_rec_window;
  
  channel->flags = 0;
  channel->sources = 0;
  
  channel->request_types = NULL;
  channel->receive = NULL;
  channel->send = NULL;

  channel->close = NULL;
  channel->eof = NULL;

  channel->open_continuation = NULL;

  channel->resources = empty_resource_list();
  
  object_queue_init(&channel->pending_requests);
}

struct lsh_string *channel_transmit_data(struct ssh_channel *channel,
					 struct lsh_string *data)
{
  assert(data->length <= channel->send_window_size);
  assert(data->length <= channel->send_max_packet);
  
  return ssh_format("%c%i%fS",
		    SSH_MSG_CHANNEL_DATA,
		    channel->channel_number,
		    data);
}

struct lsh_string *channel_transmit_extended(struct ssh_channel *channel,
					     UINT32 type,
					     struct lsh_string *data)
{
  assert(data->length <= channel->send_window_size);
  assert(data->length <= channel->send_max_packet);
  
  return ssh_format("%c%i%i%fS",
		    SSH_MSG_CHANNEL_EXTENDED_DATA,
		    channel->channel_number,
		    type,
		    data);
}

/* Writing data to a channel */
/* GABA:
   (class
     (name channel_write)
     (super abstract_write)
     (vars
       (channel object ssh_channel)))
*/

/* GABA:
   (class
     (name channel_write_extended)
     (super channel_write)
     (vars
       (type simple UINT32)))
*/

static void
do_channel_write(struct abstract_write *w,
		 struct lsh_string *packet)
{
  CAST(channel_write, closure, w);

  if (!packet)
    {
      /* EOF */
      assert(closure->channel->sources);
      if (closure->channel->sources == 1)
	channel_eof(closure->channel);
    }
  else
    A_WRITE(closure->channel->write,
	    channel_transmit_data(closure->channel, packet) );
}

static void
do_channel_write_extended(struct abstract_write *w,
			  struct lsh_string *packet)
{
  CAST(channel_write_extended, closure, w);

  if (!packet)
    {
      /* EOF */
      assert(closure->super.channel->sources);
      if (closure->super.channel->sources == 1)
	channel_eof(closure->super.channel);
    }
  else
    A_WRITE(closure->super.channel->write,
	    channel_transmit_extended(closure->super.channel,
				      closure->type,
				      packet));
}

struct abstract_write *
make_channel_write(struct ssh_channel *channel)
{
  NEW(channel_write, closure);
  
  closure->super.write = do_channel_write;
  closure->channel = channel;

  return &closure->super;
}

struct abstract_write *
make_channel_write_extended(struct ssh_channel *channel,
			    UINT32 type)
{
  NEW(channel_write_extended, closure);

  closure->super.super.write = do_channel_write_extended;
  closure->super.channel = channel;
  closure->type = type;
  
  return &closure->super.super;
}

struct io_read_callback *
make_channel_read_data(struct ssh_channel *channel)
{
  return make_read_data(channel, make_channel_write(channel));
}

struct io_read_callback *
make_channel_read_stderr(struct ssh_channel *channel)
{
  return make_read_data(channel,
			make_channel_write_extended(channel,
						    SSH_EXTENDED_DATA_STDERR));
}    

/* GABA:
   (class
     (name channel_close_callback)
     (super close_callback)
     (vars
       (channel object ssh_channel)))
*/

#if 0
/* Close callback for files we are writing to. */
static void
channel_close_write_callback(struct close_callback *c, int reason)
{
  CAST(channel_close_callback, closure, c);

  switch (reason)
    {
    case CLOSE_EOF:
      /* Expected close: Do nothing */
      debug("channel_close_callback: Closing after EOF.\n");
      break;

    default:
      if (closure->channel->flags & CHANNEL_SENT_CLOSE)
	/* Do nothing */
	break;
      /* Fall through to send CHANNEL_CLOSE message */
    case CLOSE_WRITE_FAILED:
    case CLOSE_BROKEN_PIPE:
      channel_close(closure->channel);
      break;
    }
}

struct close_callback *
make_channel_write_close_callback(struct ssh_channel *channel)
{
  NEW(channel_close_callback, closure);
  
  closure->super.f = channel_close_write_callback;
  closure->channel = channel;

  return &closure->super;
}
#endif

/* Close callback for files we are reading from, writing to (files we read from
 * doesn't need any special callback, as we'll get EOF from them).
 *
 * FIXME: I don't know how we should catch POLLERR on files we read;
 * perhaps we need this callback, or perhaps we'll install an
 * i/o-exception handler do the work. */

static void
channel_read_close_callback(struct close_callback *c, int reason)
{
  CAST(channel_close_callback, closure, c);

  debug("channel_read_close_callback: File closed for reason %i.\n",
	reason);

  assert(closure->channel->sources);
  
  if (!--closure->channel->sources)
    {
      /* Send eof, unless already done */
      channel_eof(closure->channel);
    }
}

struct close_callback *
make_channel_read_close_callback(struct ssh_channel *channel)
{
  NEW(channel_close_callback, closure);
  
  closure->super.f = channel_read_close_callback;
  closure->channel = channel;

  return &closure->super;
}

/* Exception handler that closes the channel on I/O errors.
 * Primarily used for write fd:s that the channel is fed into.
 *
 * FIXME: Ideally, I'd like to pass something like broken pipe to the
 * other end, on write errors, but I don't see how to do that. */

/* GABA:
   (class
     (name channel_io_exception_handler)
     (super exception_handler)
     (vars
       (channel object ssh_channel)
       (prefix . "const char *")))
*/

static void
do_channel_io_exception_handler(struct exception_handler *s,
				const struct exception *x)
{
  CAST(channel_io_exception_handler, self, s);
  if (x->type & EXC_IO)
    {
      werror("channel.c: I/O error on write, %z\n", x->msg);
#if 0
      send_debug_message(self->channel->write,
			 ssh_format("%z I/O error: %z\n",
				    self->prefix, x->msg),
			 1);
#endif
      channel_close(self->channel);
    }
  else
    EXCEPTION_RAISE(s->parent, x);
}

struct exception_handler *
make_channel_io_exception_handler(struct ssh_channel *channel,
				  const char *prefix,
				  struct exception_handler *parent,
				  const char *context)
{
  NEW(channel_io_exception_handler, self);
  self->super.raise = do_channel_io_exception_handler;
  self->super.parent = parent;
  self->super.context = context;
  
  self->channel = channel;
  self->prefix = prefix;

  return &self->super;
}

struct lsh_string *
prepare_channel_open(struct ssh_connection *connection,
		     int type, struct ssh_channel *channel,
		     const char *format, ...)
{
  int index;
    
  va_list args;
  UINT32 l1, l2;
  struct lsh_string *packet;
  
#define OPEN_FORMAT "%c%a%i%i%i"
#define OPEN_ARGS SSH_MSG_CHANNEL_OPEN, type, (UINT32) index, \
  channel->rec_window_size, channel->rec_max_packet  

  debug("prepare_channel_open: rec_window_size = %i,\n"
	"                      rec_max_packet = %i,\n"
	"                      max_packet = %i\n",
	channel->rec_window_size,
	channel->rec_max_packet,
	channel->max_window);
  
  index = alloc_channel(connection->table);

  if (index < 0)
    return 0;

  register_channel(connection, index, channel);

  l1 = ssh_format_length(OPEN_FORMAT, OPEN_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(OPEN_FORMAT, l1, packet->data, OPEN_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, l2, packet->data+l1, args);
  va_end(args);

  return packet;
#undef OPEN_FORMAT
#undef OPEN_ARGS
}
		   
struct lsh_string *
format_channel_request(int type, struct ssh_channel *channel,
		       int want_reply, const char *format, 
		       ...)
{
  va_list args;
  UINT32 l1, l2;
  struct lsh_string *packet;

#define REQUEST_FORMAT "%c%i%a%c"
#define REQUEST_ARGS SSH_MSG_CHANNEL_REQUEST, channel->channel_number, \
  type, want_reply
    
  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, l1, packet->data, REQUEST_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, l2, packet->data+l1, args);
  va_end(args);

  return packet;
#undef REQUEST_FORMAT
#undef REQUEST_ARGS
}
  
