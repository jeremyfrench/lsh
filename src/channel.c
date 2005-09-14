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
#include "read_data.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "channel.h.x"
#undef GABA_DEFINE

#include "channel.c.x"

/* FIXME: Kludgy. Turn into a function or method? */
#undef PROTOCOL_ERROR

#define PROTOCOL_ERROR(table, msg)								\
do {												\
  CHANNEL_TABLE_WRITE((table), format_disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, (msg), ""));	\
  KILL_RESOURCE(&table->super);									\
} while (0)

void
channel_pending_close(struct channel_table *table)
{
  trace("channel_pending_close\n");

  /* This method should be called before the last channel is cleaned
     up, so that the cleanup code can check the flag and do the right
     thing. */
  assert(table->channel_count);
  table->pending_close = 1;
}

struct exception *
make_channel_open_exception(uint32_t error_code, const char *msg)
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

static struct lsh_string *
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
prepare_window_adjust(struct ssh_channel *channel,
		      uint32_t add)
{
  channel->rec_window_size += add;
  
  return ssh_format("%c%i%i",
		    SSH_MSG_CHANNEL_WINDOW_ADJUST,
		    channel->remote_channel_number, add);
}

static void
channel_finished(struct ssh_channel *channel)
{
  if (!channel->super.alive)
    werror("channel_finished called on a dead channel.\n");
  else
    {
      struct channel_table *table = channel->table;

      trace("channel_finished: Deallocating channel %i\n", channel->local_channel_number);
      KILL_RESOURCE(&channel->super);

      /* Disassociate from the connection. */
      channel->table = NULL;
      
      dealloc_channel(table, channel->local_channel_number);

      trace("table->pending_close = %i, table->channel_count = %i\n",
	    table->pending_close, table->channel_count);

      if (table->pending_close && !table->channel_count)
	KILL_RESOURCE(&table->super);
    }
}


/* Channel objects */

#define INITIAL_CHANNELS 32
/* Arbitrary limit */
#define MAX_CHANNELS (1L<<17)

void
init_channel_table(struct channel_table *table,
		   void (*kill)(struct resource *),
		   void (*write)(struct channel_table *, struct lsh_string *))
{
  init_resource(&table->super, kill);

  table->write = write;

  /* FIXME: Really need this? */
  table->chain = NULL;

  table->channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				      * INITIAL_CHANNELS);
  table->in_use = lsh_space_alloc(INITIAL_CHANNELS);
  
  table->allocated_channels = INITIAL_CHANNELS;
  table->used_channels = 0;
  table->next_channel = 0;
  table->channel_count = 0;
  
  table->max_channels = MAX_CHANNELS;

  table->pending_close = 0;

  table->global_requests = make_alist(0, -1);
  table->channel_types = make_alist(0, -1);
  table->open_fallback = NULL;
  
  object_queue_init(&table->local_ports);
  object_queue_init(&table->remote_ports);
  table->x11_display = NULL;
  
  object_queue_init(&table->active_global_requests);
  object_queue_init(&table->pending_global_requests);
}

void
kill_channels(struct channel_table *table)
{
  uint32_t i;

  for (i = 0; i<table->used_channels; i++)
    {
      /* Loop over all channels, no matter if the status is reserved or in use */
      struct ssh_channel *channel = table->channels[i];

      if (channel)
	KILL_RESOURCE(&channel->super);
    }
}

/* Returns -1 if allocation fails */
/* NOTE: This function returns locally chosen channel numbers, which
 * are always small integers. So there's no problem fitting them in
 * a signed int. */
int
alloc_channel(struct channel_table *table)
{
  uint32_t i;
  
  for (i = table->next_channel; i < table->used_channels; i++)
    {
      if (table->in_use[i] == CHANNEL_FREE)
	{
	  assert(!table->channels[i]);
	  table->in_use[i] = CHANNEL_RESERVED;
	  table->next_channel = i+1;

	  goto success;
	}
    }
  if (i == table->max_channels)
    return -1;

  if (i == table->allocated_channels) 
    {
      uint32_t new_size = table->allocated_channels * 2;
      struct ssh_channel **new_channels;
      uint8_t *new_in_use;

      new_channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				     * new_size);
      memcpy(new_channels, table->channels,
	     sizeof(struct ssh_channel *) * table->used_channels);
      lsh_space_free(table->channels);
      table->channels = new_channels;

      /* FIXME: Use realloc(). */
      new_in_use = lsh_space_alloc(new_size);
      memcpy(new_in_use, table->in_use, table->used_channels);
      lsh_space_free(table->in_use);
      table->in_use = new_in_use;

      table->allocated_channels = new_size;
    }

  table->next_channel = table->used_channels = i+1;

  table->in_use[i] = CHANNEL_RESERVED;
  table->channels[i] = NULL;
  
 success:
  table->channel_count++;
  verbose("Allocated local channel number %i\n", i);

  return i;
}

void
dealloc_channel(struct channel_table *table, int i)
{
  assert(i >= 0);
  assert( (unsigned) i < table->used_channels);
  assert(table->channel_count);
  
  verbose("Deallocating local channel %i\n", i);
  table->channels[i] = NULL;
  table->in_use[i] = CHANNEL_FREE;

  table->channel_count--;
  
  if ( (unsigned) i < table->next_channel)
    table->next_channel = i;
}

void
use_channel(struct ssh_channel *channel)
{
  struct channel_table *table = channel->table;
  uint32_t local_channel_number = channel->local_channel_number;
  
  assert(table->channels[local_channel_number] == channel);
  assert(table->in_use[local_channel_number] == CHANNEL_RESERVED);
  
  table->in_use[local_channel_number] = CHANNEL_IN_USE;
  verbose("Taking channel %i in use, (local %i).\n",
	  channel->remote_channel_number, local_channel_number);
}

void
register_channel(struct channel_table *table,
		 uint32_t local_channel_number,
		 struct ssh_channel *channel,
		 int take_into_use)
{
  assert(table->in_use[local_channel_number] == CHANNEL_RESERVED);
  assert(!table->channels[local_channel_number]);

  verbose("Registering local channel %i.\n",
	  local_channel_number);

  table->channels[local_channel_number] = channel;
  channel->local_channel_number = local_channel_number;

  if (take_into_use)
    use_channel(channel);
}

/* FIXME: Move the reserved flag into the channel class? */
struct ssh_channel *
lookup_channel(struct channel_table *table, uint32_t i)
{
  if ( (i < table->used_channels) && (table->in_use[i] == CHANNEL_IN_USE))
    {
      struct ssh_channel *channel = table->channels[i];
      assert(channel);
      assert(channel->local_channel_number == i);

      return channel;
    }
  return NULL;
}

struct ssh_channel *
lookup_channel_reserved(struct channel_table *table, uint32_t i)
{
  if ( (i < table->used_channels) && (table->in_use[i] == CHANNEL_RESERVED))
    {
      struct ssh_channel *channel = table->channels[i];
      assert(channel);
      assert(channel->local_channel_number == i);

      return channel;
    }
  return NULL;
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
  if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE
			   | CHANNEL_SENT_CLOSE)))
    CHANNEL_TABLE_WRITE(channel->table, prepare_window_adjust(channel, written));
}

void
channel_start_receive(struct ssh_channel *channel,
		      uint32_t initial_window_size)
{
  if (channel->rec_window_size < initial_window_size)
    CHANNEL_TABLE_WRITE(channel->table,
		 prepare_window_adjust
		 (channel, initial_window_size - channel->rec_window_size));
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
       (table object channel_table)
       (active object request_status)))
*/

static void 
send_global_request_responses(struct channel_table *table, 
			      struct object_queue *q)
{
   for (;;)
     {
       CAST(request_status, n, object_queue_peek_head(q));
       if (!n || (n->status < 0))
	 break;
 
      object_queue_remove_head(q);

      CHANNEL_TABLE_WRITE(table, (n->status
			   ? format_global_success()
			   : format_global_failure()));
    }
}

static void
do_global_request_response(struct command_continuation *s,
			   struct lsh_object *x UNUSED)
{
  CAST(global_request_continuation, self, s);
  struct object_queue *q = &self->table->active_global_requests;

  assert(self->active->status == -1);
  assert(!object_queue_is_empty(q));
	  
  self->active->status = 1;

  send_global_request_responses(self->table, q);
}

static struct command_continuation *
make_global_request_response(struct channel_table *table,
			     struct request_status *active)
{
  NEW(global_request_continuation, self);

  self->super.c = do_global_request_response;
  self->table = table;
  self->active = active;
   
  return &self->super;
}


/* GABA:
   (class
     (name global_request_exception_handler)
     (super exception_handler)
     (vars
       (table object channel_table)
       (active object request_status)))
*/

/* NOTE: We handle *only* EXC_GLOBAL_REQUEST */
static void 
do_exc_global_request_handler(struct exception_handler *c,
			      const struct exception *e)
{
  CAST(global_request_exception_handler, self, c);
  if (e->type == EXC_GLOBAL_REQUEST)
    {
      struct object_queue *q = &self->table->active_global_requests;
      
      assert(self->active->status == -1);
      assert(!object_queue_is_empty(q));

      self->active->status = 0;
  
      send_global_request_responses(self->table, q);
    }
  else
    EXCEPTION_RAISE(c->parent, e);
}

static struct exception_handler *
make_global_request_exception_handler(struct channel_table *table,
				      struct request_status *active,
				      struct exception_handler *h,
				      const char *context)
{
  NEW(global_request_exception_handler, self);

  self->super.raise = do_exc_global_request_handler;
  self->super.context = context;
  self->super.parent = h;
  self->active = active;
  self->table = table;
  return &self->super;
}

static void
handle_global_request(struct channel_table *table,
		      struct simple_buffer *buffer)
{
  int name;
  int want_reply;
  
  if (parse_atom(buffer, &name)
      && parse_boolean(buffer, &want_reply))
    {
      struct global_request *req = NULL;
      struct command_continuation *c = &discard_continuation;

      if (name && table->global_requests)
	{
	  CAST_SUBTYPE(global_request, r,
		       ALIST_GET(table->global_requests,
				 name));
	  req = r;
	}
      if (!req)
	{
	  CHANNEL_TABLE_WRITE(table, format_global_failure());
	  return;
	}
      else
	{
	  struct exception_handler *e;
	  if (want_reply)
	    {
	      struct request_status *a = make_request_status();
	      
	      object_queue_add_tail(&table->active_global_requests,
				    &a->super);
	      
	      c = make_global_request_response(table, a);
	      e = make_global_request_exception_handler(table, a, &default_exception_handler,
							HANDLER_CONTEXT);
	    }
	  else
	    {
	      /* We should ignore failures. */
	      static const struct report_exception_info global_req_ignore =
		STATIC_REPORT_EXCEPTION_INFO(EXC_ALL, EXC_GLOBAL_REQUEST,
					     "Ignored:");
	      
	      e = make_report_exception_handler(&global_req_ignore,
						&default_exception_handler, HANDLER_CONTEXT);
	    }
	  GLOBAL_REQUEST(req, table, name, want_reply, buffer, c, e);
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid SSH_MSG_GLOBAL_REQUEST message.");
}

static void
handle_global_success(struct channel_table *table,
		      struct simple_buffer *buffer)
{
  if (!parse_eod(buffer))
    {
      PROTOCOL_ERROR(table, "Invalid GLOBAL_REQUEST_SUCCESS message.");
      return;
    }

  if (object_queue_is_empty(&table->pending_global_requests))
    {
      werror("do_global_request_success: Unexpected message, ignoring.\n");
      return;
    }
  {
    CAST_SUBTYPE(command_context, ctx,
		 object_queue_remove_head(&table->pending_global_requests));
    COMMAND_RETURN(ctx->c, table);
  }
}

struct exception global_request_exception =
STATIC_EXCEPTION(EXC_GLOBAL_REQUEST, "Global request failed");

static void
handle_global_failure(struct channel_table *table,
		      struct simple_buffer *buffer)
{
  if (!parse_eod(buffer))
    {
      PROTOCOL_ERROR(table, "Invalid GLOBAL_REQUEST_FAILURE message.");
      return;
    }

  if (object_queue_is_empty(&table->pending_global_requests))
    {
      werror("do_global_request_failure: Unexpected message, ignoring.\n");
    }
  else
    {
      CAST_SUBTYPE(command_context, ctx,
		   object_queue_remove_head(&table->pending_global_requests));
      EXCEPTION_RAISE(ctx->e, &global_request_exception);
    }
}

/* FIXME: Don't store the channel here, instead have it passed as the
 * argument of the continuation. This might also allow some
 * unification with the handling of global_requests.
 *
 * This won't quite work yet, because not all channel request
 * handlers, in particular gateway_channel_request and
 * x11_req_handler, return the channel in question. */

/* GABA:
   (class
     (name channel_request_continuation)
     (super command_continuation)
     (vars
       (channel object ssh_channel)
       (active object request_status)))
*/

/* FIXME: Queue argument is unnecessary */
static void
send_channel_request_responses(struct ssh_channel *channel,
			       struct object_queue *q)
{
  for (;;)
    {
      CAST(request_status, n, object_queue_peek_head(q));
      if (!n || (n->status < 0))
	break;

      object_queue_remove_head(q);

      CHANNEL_TABLE_WRITE(channel->table,
		   (n->status
		    ? format_channel_success(channel->remote_channel_number)
		    : format_channel_failure(channel->remote_channel_number)));
    }
}

static void
do_channel_request_response(struct command_continuation *s,
			    struct lsh_object *x UNUSED)
{
  CAST(channel_request_continuation, self, s);
  struct object_queue *q = &self->channel->active_requests;

  trace("do_channel_request_response\n");
  assert(self->active->status == -1);
  assert(!object_queue_is_empty(q));
	  
  self->active->status = 1;

  send_channel_request_responses(self->channel, q);
}

static struct command_continuation *
make_channel_request_response(struct ssh_channel *channel,
			      struct request_status *active)
{
  NEW(channel_request_continuation, self);

  trace("make_channel_request_response\n");

  self->super.c = do_channel_request_response;
  self->channel = channel;
  self->active = active;

  return &self->super;
}

/* GABA:
   (class
     (name channel_request_exception_handler)
     (super exception_handler)
     (vars
       (channel object ssh_channel)
       (active object request_status)))
*/

/* NOTE: We handle *only* EXC_CHANNEL_REQUEST */
static void 
do_exc_channel_request_handler(struct exception_handler *c,
			       const struct exception *e)
{
  CAST(channel_request_exception_handler, self, c);
  if (e->type == EXC_CHANNEL_REQUEST)
    {
      struct object_queue *q = &self->channel->active_requests;

      assert(self->active->status == -1);
      assert(!object_queue_is_empty(q));
      
      self->active->status = 0;
      
      send_channel_request_responses(self->channel, q);
    }
  else
    EXCEPTION_RAISE(c->parent, e);
}

static struct exception_handler *
make_channel_request_exception_handler(struct ssh_channel *channel,
				       struct request_status *active,
				       struct exception_handler *h,
				       const char *context)
{
  NEW(channel_request_exception_handler, self);

  self->super.raise = do_exc_channel_request_handler;
  self->super.parent = h;
  self->super.context = context;

  self->channel = channel;
  self->active = active;

  return &self->super;
}

/* FIXME: Inline in caller */
static int
parse_channel_request(struct simple_buffer *buffer,
		      uint32_t *channel_number,
		      struct channel_request_info *info)
{
  if (parse_uint32(buffer, channel_number)
      && parse_string(buffer,
		      &info->type_length, &info->type_data)
      && parse_boolean(buffer, &info->want_reply))
    {
      info->type = lookup_atom(info->type_length, info->type_data);
      return 1;
    }
  else
    return 0;
}

static void
handle_channel_request(struct channel_table *table,
		       struct simple_buffer *buffer)
{
  struct channel_request_info info;
  uint32_t channel_number;
  
  if (parse_channel_request(buffer, &channel_number, &info))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

      /* NOTE: We can't free packet yet, because it is not yet fully
       * parsed. There may be some more arguments, which are parsed by
       * the CHANNEL_REQUEST method below. */

      if (channel)
	{
	  struct channel_request *req = NULL;
	  struct command_continuation *c = &discard_continuation;
	  struct exception_handler *e = channel->e;

	  if (info.type && channel->request_types)
	    {
	      CAST_SUBTYPE(channel_request, r,
			   ALIST_GET(channel->request_types, info.type));
	      req = r;
	    }
	  if (!req)
	    req = channel->request_fallback;
	  
	  if (req)
	    {
	      if (info.want_reply)
		{
		  struct request_status *a = make_request_status();

		  object_queue_add_tail(&channel->active_requests,
					&a->super);

		  c = make_channel_request_response(channel, a);
		  e = make_channel_request_exception_handler(channel, a, e, HANDLER_CONTEXT);
		}
	      else
		{
		  /* We should ignore failures. */
		  static const struct report_exception_info
		    channel_req_ignore =
		    STATIC_REPORT_EXCEPTION_INFO(EXC_ALL, EXC_CHANNEL_REQUEST,
						 "Ignored:");
		  
		  e = make_report_exception_handler(&channel_req_ignore,
						    e, HANDLER_CONTEXT);
		}
	      
	      CHANNEL_REQUEST(req, channel, &info, buffer, c, e);
	    }
	  else
	    {
	      if (info.want_reply)
		CHANNEL_TABLE_WRITE(table,
				    format_channel_failure(channel->remote_channel_number));
	    }
	}
      else
	{
	  werror("SSH_MSG_CHANNEL_REQUEST on nonexistant channel %i: %xs\n",
		 channel_number, buffer->capacity, buffer->pos);
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid SSH_MSG_CHANNEL_REQUEST message.");
}


/* GABA:
   (class
     (name channel_open_continuation)
     (super command_continuation)
     (vars
       (table object channel_table)
       (local_channel_number . uint32_t)
       (remote_channel_number . uint32_t)
       (send_window_size . uint32_t)
       (send_max_packet . uint32_t)))
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
  channel->send_window_size = self->send_window_size;
  channel->send_max_packet = self->send_max_packet;
  channel->remote_channel_number = self->remote_channel_number;

  channel->table = self->table;
  
  register_channel(self->table, self->local_channel_number,
		   channel,
		   1);

  /* FIXME: Doesn't support sending extra arguments with the
   * confirmation message. */

  CHANNEL_TABLE_WRITE(self->table,
	       format_open_confirmation(channel, ""));
}

static struct command_continuation *
make_channel_open_continuation(struct channel_table *table,
			       uint32_t local_channel_number,
			       uint32_t remote_channel_number,
			       uint32_t send_window_size,
			       uint32_t send_max_packet)
{
  NEW(channel_open_continuation, self);

  self->super.c = do_channel_open_continue;
  self->table = table;
  self->local_channel_number = local_channel_number;
  self->remote_channel_number = remote_channel_number;
  self->send_window_size = send_window_size;
  self->send_max_packet = send_max_packet;

  return &self->super;
}
			       
/* GABA:
   (class
     (name exc_channel_open_handler)
     (super exception_handler)
     (vars
       (table object channel_table)
       (local_channel_number . uint32_t)
       (remote_channel_number . uint32_t)))
*/

static void
do_exc_channel_open_handler(struct exception_handler *s,
			    const struct exception *e)
{
  CAST(exc_channel_open_handler, self, s);

  switch (e->type)
    {
    case EXC_CHANNEL_OPEN:
      {
	CAST_SUBTYPE(channel_open_exception, exc, e);
	struct channel_table *table = self->table;
	
	assert(table->in_use[self->local_channel_number]);
	assert(!table->channels[self->local_channel_number]);

	dealloc_channel(table, self->local_channel_number);
	
        CHANNEL_TABLE_WRITE(table,
		     format_open_failure(self->remote_channel_number,
					 exc->error_code, e->msg, ""));
	break;
      }
    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }      
}

static struct exception_handler *
make_exc_channel_open_handler(struct channel_table *table,
			      uint32_t local_channel_number,
			      uint32_t remote_channel_number,
			      struct exception_handler *parent,
			      const char *context)
{
  NEW(exc_channel_open_handler, self);
  self->super.parent = parent;
  self->super.raise = do_exc_channel_open_handler;
  self->super.context = context;
  
  self->table = table;
  self->local_channel_number = local_channel_number;
  self->remote_channel_number = remote_channel_number;

  return &self->super;
}

/* FIXME: Inline in caller */
static int
parse_channel_open(struct simple_buffer *buffer,
		   struct channel_open_info *info)
{
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
	  werror("do_channel_open: The remote end asked for really large packets.\n");
	  info->send_max_packet = SSH_MAX_PACKET;
	}

      return 1;
    }
  else
    return 0;
}

static void
handle_channel_open(struct channel_table *table,
		    struct simple_buffer *buffer)
{
  struct channel_open_info info;

  trace("handle_channel_open\n");
  
  if (parse_channel_open(buffer, &info))
    {
      struct channel_open *open = NULL;

      /* NOTE: We can't free the packet yet, as the buffer is passed
       * to the CHANNEL_OPEN method later. */

      if (table->pending_close)
	{
	  /* We are waiting for channels to close. Don't open any new ones. */

	  CHANNEL_TABLE_WRITE(table,
		       format_open_failure(
			 info.remote_channel_number,
			 SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
			 "Waiting for channels to close.", ""));
	}
      else
	{
	  if (info.type)
	    {
	      CAST_SUBTYPE(channel_open, o,
			   ALIST_GET(table->channel_types,
				     info.type));
	      open = o;
	    }

	  if (!open)
	    open = table->open_fallback;
	  
	  if (!open)
	    {
	      werror("handle_channel_open: Unknown channel type `%ps'\n",
		     info.type_length, info.type_data);
	      CHANNEL_TABLE_WRITE(table,
			   format_open_failure(
			     info.remote_channel_number,
			     SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
			     "Unknown channel type", ""));
	    }
	  else
	    {
	      int local_number = alloc_channel(table);

	      if (local_number < 0)
		{
		  CHANNEL_TABLE_WRITE(table,
			       format_open_failure(
				 info.remote_channel_number,
				 SSH_OPEN_RESOURCE_SHORTAGE,
				 "Channel limit exceeded.", ""));
		  return;
		}
	      
	      CHANNEL_OPEN(open, table,
			   &info,
			   buffer,
			   make_channel_open_continuation(table,
							  local_number,
							  info.remote_channel_number,
							  info.send_window_size,
							  info.send_max_packet),
			   make_exc_channel_open_handler(table,
							 local_number,
							 info.remote_channel_number,
							 &default_exception_handler,
							 HANDLER_CONTEXT));

	    }
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid SSH_MSG_CHANNEL_OPEN message.");
}     

static void
handle_adjust_window(struct channel_table *table,
		     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t size;

  if (parse_uint32(buffer, &channel_number)
      && parse_uint32(buffer, &size)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

      if (channel
	  && !(channel->flags & CHANNEL_RECEIVED_CLOSE))
	{
	  if (! (channel->flags & (CHANNEL_SENT_CLOSE | CHANNEL_SENT_EOF)))
	    {
	      channel->send_window_size += size;

	      if (channel->send_window_size && channel->send_adjust)
		CHANNEL_SEND_ADJUST(channel, size);
	    }
	}
      else
	{
	  werror("SSH_MSG_CHANNEL_WINDOW_ADJUST on nonexistant or closed "
		 "channel %i\n", channel_number);
	  PROTOCOL_ERROR(table, "Unexpected CHANNEL_WINDOW_ADJUST");
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_WINDOW_ADJUST message.");
}

static void
handle_channel_data(struct channel_table *table,
		    struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct lsh_string *data;
  
  if (parse_uint32(buffer, &channel_number)
      && ( (data = parse_string_copy(buffer)) )
      && parse_eod(buffer))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

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
	      uint32_t length = lsh_string_length(data);
              if (length > channel->rec_max_packet)
                {
                  werror("Channel data larger than rec_max_packet. Extra data ignored.\n");
		  lsh_string_trunc(data, channel->rec_max_packet);
                }

	      if (length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel data overflow. Extra data ignored.\n");
		  debug("   (data->length=%i, rec_window_size=%i).\n", 
			length, channel->rec_window_size);

		  lsh_string_trunc(data, channel->rec_window_size);
		}

	      if (!length)
		{
		  /* Ignore data packet */
		  lsh_string_free(data);
		  return;
		}
	      channel->rec_window_size -= length;

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
    PROTOCOL_ERROR(table, "Invalid CHANNEL_DATA message.");
}

static void
handle_channel_extended_data(struct channel_table *table,
			     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  uint32_t type;
  struct lsh_string *data;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_uint32(buffer, &type)
      && ( (data = parse_string_copy(buffer)) )
      && parse_eod(buffer))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

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
	      uint32_t length = lsh_string_length(data);
              if (length > channel->rec_max_packet)
                {
                  werror("Channel data larger than rec_max_packet. Extra data ignored.\n");
		  lsh_string_trunc(data, channel->rec_max_packet);
                }

	      if (length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel extended data overflow. "
			 "Extra data ignored.\n");
		  debug("   (data->length=%i, rec_window_size=%i).\n", 
			length, channel->rec_window_size);

		  lsh_string_trunc(data, channel->rec_window_size);
		}
	      
	      if (!length)
		{
		  /* Ignore data packet */
		  lsh_string_free(data);
		  return;
		}

	      channel->rec_window_size -= length;

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
    PROTOCOL_ERROR(table, "Invalid CHANNEL_EXTENDED_DATA message.");
}

static void
handle_channel_eof(struct channel_table *table,
		   struct simple_buffer *buffer)
{
  uint32_t channel_number;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

      if (channel)
	{
	  if (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE))
	    {
	      werror("Receiving EOF on channel on closed channel.\n");
	      PROTOCOL_ERROR(table,
			     "Received EOF on channel on closed channel.");
	    }
	  else
	    {
	      verbose("Receiving EOF on channel %i (local %i)\n",
		      channel->remote_channel_number, channel_number);
	      
	      channel->flags |= CHANNEL_RECEIVED_EOF;
	      
	      if (channel->eof)
		{
		  CHANNEL_EOF(channel);

		  /* Should we close the channel now? */
		  channel_maybe_close(channel);
		}
	      else
		{
		  /* By default, close the channel. */
		  debug("No CHANNEL_EOF handler. Closing.\n"); 
		  channel_close(channel);
		}
	      
	    }
	}
      else
	{
	  werror("EOF on non-existant channel %i\n",
		 channel_number);
	  PROTOCOL_ERROR(table, "EOF on non-existant channel");
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_EOF message");
}

static void
handle_channel_close(struct channel_table *table,
		     struct simple_buffer *buffer)
{
  uint32_t channel_number;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer))
    {
      struct ssh_channel *channel = lookup_channel(table, channel_number);

      if (channel)
	{
	  verbose("Receiving CLOSE on channel %i (local %i)\n",
		  channel->remote_channel_number, channel_number);
	      
	  if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	    {
	      werror("Receiving multiple CLOSE on channel.\n");
	      PROTOCOL_ERROR(table, "Receiving multiple CLOSE on channel.");
	    }
	  else
	    {
	      channel->flags |= CHANNEL_RECEIVED_CLOSE;
	  
	      if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_NO_WAIT_FOR_EOF
				       | CHANNEL_SENT_CLOSE)))
		{
		  werror("Unexpected channel CLOSE.\n");
		}

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
	  PROTOCOL_ERROR(table, "CLOSE on non-existant channel");
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_CLOSE message");
}

static void
handle_open_confirm(struct channel_table *table,
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
      struct ssh_channel *channel =
	lookup_channel_reserved(table, local_channel_number);

      if (channel) 
	{
	  struct command_continuation *c = channel->open_continuation;
	  assert(c);

	  channel->open_continuation = NULL;

	  channel->remote_channel_number = remote_channel_number;
	  channel->send_window_size = window_size;
	  channel->send_max_packet = max_packet;

	  use_channel(channel);

	  COMMAND_RETURN(c, channel);
	}
      else
	{
	  werror("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel %i\n",
		 local_channel_number);
	  PROTOCOL_ERROR(table, "Unexpected CHANNEL_OPEN_CONFIRMATION.");
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_OPEN_CONFIRMATION message.");
}

static void
handle_open_failure(struct channel_table *table,
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
	lookup_channel_reserved(table, channel_number);

      if (channel)
	{
	  assert(channel->open_continuation);
	  
	  /* FIXME: It would be nice to pass the message on. */
	  werror("Channel open for channel %i failed: %ps\n", channel_number, length, msg);

	  EXCEPTION_RAISE(channel->e,
			  make_channel_open_exception(reason, "Channel open refused by peer"));
	  channel_finished(channel);
	}
      else
	werror("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE on channel %i\n",
	       channel_number);
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_OPEN_FAILURE message.");
}

static void
handle_channel_success(struct channel_table *table,
		       struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct ssh_channel *channel;
      
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer)
      && (channel = lookup_channel(table, channel_number)))
    {
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
    PROTOCOL_ERROR(table, "Invalid CHANNEL_SUCCESS message");
}

static void
handle_channel_failure(struct channel_table *table,
		       struct simple_buffer *buffer)
{
  uint32_t channel_number;
  struct ssh_channel *channel;
  
  if (parse_uint32(buffer, &channel_number)
      && parse_eod(buffer)
      && (channel = lookup_channel(table, channel_number)))
    {
      if (object_queue_is_empty(&channel->pending_requests))
	{
	  werror("do_channel_failure: No handler. Ignoring.\n");
	}
      else
	{
	  static const struct exception channel_request_exception =
	    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Channel request failed");

	  CAST_SUBTYPE(command_context, ctx,
		       object_queue_remove_head(&channel->pending_requests));
	  
	  EXCEPTION_RAISE(ctx->e, &channel_request_exception);
	}
    }
  else
    PROTOCOL_ERROR(table, "Invalid CHANNEL_FAILURE message.");
}

struct lsh_string *
format_channel_close(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_CLOSE,
		    channel->remote_channel_number);
}

void
channel_close(struct ssh_channel *channel)
{
  if (! (channel->flags & CHANNEL_SENT_CLOSE))
    {
      verbose("Sending CLOSE on channel %i\n", channel->remote_channel_number);

      channel->flags |= CHANNEL_SENT_CLOSE;
      
      CHANNEL_TABLE_WRITE(channel->table, format_channel_close(channel));

      if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	channel_finished(channel);
    }
}

/* Implement the close logic */
void
channel_maybe_close(struct ssh_channel *channel)
{
  if (channel->flags & CHANNEL_SENT_CLOSE)
    return;

  if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_NO_WAIT_FOR_EOF)))
    return;

  if ( (channel->flags & CHANNEL_SENT_EOF) && !channel->sources && !channel->sinks)
    channel_close(channel);      
}

struct lsh_string *
format_channel_eof(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_EOF,
		    channel->remote_channel_number);
}

void
channel_eof(struct ssh_channel *channel)
{
  if (! (channel->flags &
	 (CHANNEL_SENT_EOF | CHANNEL_SENT_CLOSE | CHANNEL_RECEIVED_CLOSE)))
    {
      verbose("Sending EOF on channel %i\n", channel->remote_channel_number);

      channel->flags |= CHANNEL_SENT_EOF;
      CHANNEL_TABLE_WRITE(channel->table, format_channel_eof(channel) );

      channel_maybe_close(channel);
    }
}

void
init_channel(struct ssh_channel *channel,
	     void (*kill)(struct resource *))
{
  init_resource(&channel->super, kill);

  channel->table = NULL;
  
  channel->flags = 0;
  channel->sources = 0;
  channel->sinks = 0;

  channel->request_types = NULL;
  channel->request_fallback = NULL;
  
  channel->receive = NULL;
  channel->send_adjust = NULL;

  channel->eof = NULL;

  channel->open_continuation = NULL;

  object_queue_init(&channel->pending_requests);
  object_queue_init(&channel->active_requests);
}

/* Returns zero if message type is unimplemented */
int
channel_packet_handler(struct channel_table *table,
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
      handle_global_request(table, &buffer);
      break;
    case SSH_MSG_REQUEST_SUCCESS:
      handle_global_success(table, &buffer);
      break;
    case SSH_MSG_REQUEST_FAILURE:
      handle_global_failure(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN:
      handle_channel_open(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      handle_open_confirm(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
      handle_open_failure(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
      handle_adjust_window(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_DATA:
      handle_channel_data(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_EXTENDED_DATA:
      handle_channel_extended_data(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_EOF:
      handle_channel_eof(table, &buffer);
      break;
    case SSH_MSG_CHANNEL_CLOSE:
      handle_channel_close(table, &buffer);       
      break;
    case SSH_MSG_CHANNEL_REQUEST:
      handle_channel_request(table, &buffer); 
      break;
    case SSH_MSG_CHANNEL_SUCCESS:
      handle_channel_success(table, &buffer); 
      break;
    case SSH_MSG_CHANNEL_FAILURE:
      handle_channel_failure(table, &buffer); 
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

  CHANNEL_TABLE_WRITE(channel->table,
		      ssh_format("%c%i%s",
				 SSH_MSG_CHANNEL_DATA,
				 channel->remote_channel_number,
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

  CHANNEL_TABLE_WRITE(channel->table,
		      ssh_format("%c%i%i%fs",
				 SSH_MSG_CHANNEL_EXTENDED_DATA,
				 channel->remote_channel_number,
				 type, length, data));
}


/* Used by do_gateway_channel_open */
struct lsh_string *
format_channel_open_s(struct lsh_string *type,
		      uint32_t local_channel_number,
		      struct ssh_channel *channel,
		      struct lsh_string *args)
{
  check_rec_max_packet(channel);

  return ssh_format("%c%S%i%i%i%lS", SSH_MSG_CHANNEL_OPEN,
		    type, local_channel_number, 
		    channel->rec_window_size, channel->rec_max_packet,
 		    args);
}

struct lsh_string *
format_channel_open(int type, uint32_t local_channel_number,
		    struct ssh_channel *channel,
		    const char *format, ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;
  
#define OPEN_FORMAT "%c%a%i%i%i"
#define OPEN_ARGS SSH_MSG_CHANNEL_OPEN, type, local_channel_number, \
  channel->rec_window_size, channel->rec_max_packet  

  check_rec_max_packet(channel);

  debug("format_channel_open: rec_window_size = %i,\n"
	"                     rec_max_packet = %i,\n",
	channel->rec_window_size,
	channel->rec_max_packet);
  
  l1 = ssh_format_length(OPEN_FORMAT, OPEN_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(OPEN_FORMAT, packet, 0, OPEN_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

  return packet;
#undef OPEN_FORMAT
#undef OPEN_ARGS
}

struct lsh_string *
format_channel_request_i(struct channel_request_info *info,
			 struct ssh_channel *channel,
			 uint32_t args_length, const uint8_t *args_data)
{
  return ssh_format("%c%i%s%c%ls", SSH_MSG_CHANNEL_REQUEST,
		    channel->remote_channel_number,
		    info->type_length, info->type_data,
		    info->want_reply,
		    args_length, args_data);
}

struct lsh_string *
format_channel_request(int type, struct ssh_channel *channel,
		       int want_reply, const char *format, 
		       ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;

#define REQUEST_FORMAT "%c%i%a%c"
#define REQUEST_ARGS SSH_MSG_CHANNEL_REQUEST, channel->remote_channel_number, \
  type, want_reply
    
  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, packet, 0, REQUEST_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

  return packet;
#undef REQUEST_FORMAT
#undef REQUEST_ARGS
}

struct lsh_string *
format_global_request(int type, int want_reply,
		      const char *format, ...)
{
  va_list args;
  uint32_t l1, l2;
  struct lsh_string *packet;

#define REQUEST_FORMAT "%c%a%c"
#define REQUEST_ARGS SSH_MSG_GLOBAL_REQUEST, type, want_reply
    
  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, packet, 0, REQUEST_ARGS);

  va_start(args, format);
  ssh_vformat_write(format, packet, l1, args);
  va_end(args);

  return packet;
#undef REQUEST_FORMAT
#undef REQUEST_ARGS
}
