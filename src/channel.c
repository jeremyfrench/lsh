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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "channel.h"

#include "format.h"
#include "io.h"
#include "read_data.h"
#include "service.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#define CLASS_DEFINE
#include "channel.h.x"
#undef CLASS_DEFINE

#include "channel.c.x"

/* CLASS:
   (class
     (name connection_service)
     (super ssh_service)
     (vars
       ; Supported global requests 
       (global_requests object alist)

       (channel_types object alist)

       ; Initialize connection (for instance, request channels to be 
       ; opened or services to be forwarded).

       (start object connection_startup)))
*/

/* FIXME: Perhaps the channel table should be installed in the
 * connection object instead? */
/* CLASS:
   (class
     (name channel_handler)
     (super packet_handler)
     (vars
       (table object channel_table)))
*/

/* CLASS:
   (class
     (name global_request_handler)
     (super channel_handler super)
     (vars
       (global_requests object alist)))
*/

/* CLASS:
   (class
     (name channel_open_handler)
     (super channel_handler)
     (vars
       (channel_types object alist)))
*/

struct lsh_string *format_global_failure(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_FAILURE);
}

struct lsh_string *format_open_confirmation(struct ssh_channel *channel,
					    UINT32 channel_number,
					    const char *format, ...)
{
  va_list args;
  UINT32 l1, l2;
  struct lsh_string *packet;

#define CONFIRM_FORMAT "%c%i%i%i%i"
#define CONFIRM_ARGS SSH_MSG_CHANNEL_OPEN_CONFIRMATION, channel->channel_number, \
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

/* Channel objects */

#define INITIAL_CHANNELS 32
/* Arbitrary limit */
#define MAX_CHANNELS (1L<<17)

struct channel_table *make_channel_table(void)
{
  NEW(channel_table, table);

  table->channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				      * INITIAL_CHANNELS);
  table->allocated_channels = INITIAL_CHANNELS;
  table->next_channel = 0;
  table->used_channels = 0;
  table->max_channels = MAX_CHANNELS;

  table->pending_close = 0;
  
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
      if (!table->channels[i])
	{
	  table->next_channel = i+1;
	  return i;
	}
    }
  if (i == table->max_channels)
    return -1;

  if (i == table->allocated_channels) 
    {
      int new_size = table->allocated_channels * 2;
      struct ssh_channel **new
	= lsh_space_alloc(sizeof(struct ssh_channel *) * new_size);

      memcpy(new, table->channels,
	     sizeof(struct ssh_channel *) * table->used_channels);
      
      table->channels = new;
      table->allocated_channels = new_size;
    }

  table->next_channel = table->used_channels = i+1;

  return i;
}

void dealloc_channel(struct channel_table *table, int i)
{
  assert(i >= 0);
  assert( (unsigned) i < table->used_channels);
  
  table->channels[i] = NULL;

  if ( (unsigned) i < table->next_channel)
    table->next_channel = i;
}

/* Returns -1 if no channel number can be allocated. See also the note
 * for alloc_channel(). */
int register_channel(struct channel_table *table, struct ssh_channel *channel)
{
  int n = alloc_channel(table);

  if (n >= 0)
    table->channels[n] = channel;

  return n;
}

struct ssh_channel *lookup_channel(struct channel_table *table, UINT32 i)
{
  return (i < table->used_channels)
    ? table->channels[i] : NULL;
}

static int adjust_rec_window(struct ssh_channel *channel)
{
  if (channel->rec_window_size < channel->max_window / 2)
    {
      int increment = channel->max_window - channel->rec_window_size;
      channel->rec_window_size = channel->max_window;
      
      return A_WRITE(channel->write,
		     prepare_window_adjust(channel, increment));
    }
  return 0;
}

static int channel_process_status(struct channel_table *table,
				  int channel,
				  int status)
{
  struct ssh_channel *c = table->channels[channel];
  
  while (!LSH_CLOSEDP(status))
    {
      if (status & LSH_CHANNEL_READY_SEND)
	{
	  status &= ~ LSH_CHANNEL_READY_SEND;
	  if (c->send_window_size)
	    status |= CHANNEL_SEND(c);
	}
      else if (status & LSH_CHANNEL_READY_REC)
	{
	  status &= ~ LSH_CHANNEL_READY_REC;
	  status |= adjust_rec_window(c);
	}
      else
	break;
    }
	
  if (status & LSH_CHANNEL_PENDING_CLOSE)
    table->pending_close = 1;
  
  if (status & LSH_CHANNEL_FINISHED)
    {
      /* Clear this bit */
      status &= ~LSH_CHANNEL_FINISHED;

      if (c->close)
	CHANNEL_CLOSE(c);
      
      dealloc_channel(table, channel);

      /* If this was the last channel, close connection */
      if (table->pending_close && !table->next_channel)
	status |= LSH_CLOSE;
    }

  return status;
}

/* Channel related messages */
static int do_global_request(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  CAST(global_request_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  int name;
  int want_reply;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_GLOBAL_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_boolean(&buffer, &want_reply))
    {
      struct global_request *req;

      lsh_string_free(packet);
      
      if (!name || !(req = ALIST_GET(closure->global_requests, name)))
	return A_WRITE(connection->write,
		       format_global_failure());

      return GLOBAL_REQUEST(req, connection, want_reply, &buffer);
    }
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}

static int do_channel_open(struct packet_handler *c,
			   struct ssh_connection *connection,
			   struct lsh_string *packet)
{
  CAST(channel_open_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
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
      struct ssh_channel *channel;
      UINT32 error = 0;
      char *error_msg;
      struct lsh_string *args = NULL;
      
      int local_channel_number;
      
      lsh_string_free(packet);

      if (closure->super.table->pending_close)
	/* We are waiting for channels to close. Don't open any new ones. */
	return A_WRITE(connection->write,
		       format_open_failure(remote_channel_number,
					   SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
					   "Waiting for channels to close.", ""));
      
      if (!type || !(open = ALIST_GET(closure->channel_types, type)))
	return A_WRITE(connection->write,
		       format_open_failure(remote_channel_number,
					   SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
					   "Unknown channel type", ""));
      
      channel = CHANNEL_OPEN(open, connection, &buffer,
			     &error, &error_msg, &args);
      
      if (!channel)
	{
	  if (error)
	    return A_WRITE(connection->write,
			   format_open_failure(remote_channel_number,
					       error, error_msg, ""));
	  /* The request was invalid */
	  return LSH_FAIL | LSH_DIE;
	}

      if ( (local_channel_number
	    = register_channel(closure->super.table, channel)) < 0)
	{
	  wwrite("Could not allocate a channel number for pened channel!\n");
	  return A_WRITE(connection->write,
			 format_open_failure(remote_channel_number,
					     SSH_OPEN_RESOURCE_SHORTAGE,
					     "Could not allocate a channel number "
					     "(shouldn't happen...)", ""));
	}
      
      channel->send_window_size = window_size;
      channel->send_max_packet = max_packet;
      channel->channel_number = remote_channel_number;

      channel->write = connection->write;

      return A_WRITE(connection->write,
		     args
		     ? format_open_confirmation(channel, local_channel_number,
						"%lfS", args)
		     : format_open_confirmation(channel, local_channel_number,
						""));
    }
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}     

static int do_channel_request(struct packet_handler *c,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
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
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  struct channel_request *req;

	  if (type && channel->request_types 
	      && ( (req = ALIST_GET(channel->request_types, type)) ))
	    return channel_process_status
	      (closure->table, channel_number,
	       CHANNEL_REQUEST(req, channel, connection, want_reply, &buffer));
	  else
	    return want_reply
	      ? A_WRITE(connection->write,
			format_channel_failure(channel->channel_number))
	      : LSH_OK | LSH_GOON;
	  
	}
      werror("SSH_MSG_CHANNEL_REQUEST on nonexistant channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}
      
static int do_window_adjust(struct packet_handler *c,
			    struct ssh_connection *connection UNUSED,
			    struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  UINT32 size;

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_WINDOW_ADJUST)
      && parse_uint32(&buffer, &channel_number)
      && parse_uint32(&buffer, &size)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
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
		return channel_process_status(closure->table,
					      channel_number,
					      CHANNEL_SEND(channel));
	    }
	  return LSH_OK | LSH_GOON;
	}
      /* FIXME: What to do now? Should unknown channel numbers be
       * ignored silently? */
      werror("SSH_MSG_CHANNEL_WINDOW_ADJUST on nonexistant or closed channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}

static int do_channel_data(struct packet_handler *c,
			   struct ssh_connection *connection UNUSED,
			   struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  struct lsh_string *data;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_DATA)
      && parse_uint32(&buffer, &channel_number)
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->receive
	  && !(channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      wwrite("Ignoring data on channel which is closing\n");
	      return LSH_OK | LSH_GOON;
	    }
	  else
	    {
	      int res = 0;
	      
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  wwrite("Channel data overflow. Extra data ignored.\n"); 
		  data->length = channel->rec_window_size;
		}

	      if (!data->length)
		/* Ignore data packet */
		return 0;
	      channel->rec_window_size -= data->length;

	      /* FIXME: Unconditionally adjusting the receive window
	       * breaks flow control. We better let the channel's
	       * receive method decide whether or not to receive more
	       * data. */
	      res = adjust_rec_window(channel);
	      
	      if (channel->rec_window_size < channel->max_window / 2)
		{
		  res = A_WRITE(channel->write, prepare_window_adjust
				(channel,
				 channel->max_window - channel->rec_window_size));
		  if (LSH_CLOSEDP(res))
		    return res;
		}

	      return channel_process_status(
		closure->table, channel_number,
		res | CHANNEL_RECEIVE(channel, 
				      CHANNEL_DATA, data));
	    }
	  return LSH_OK | LSH_GOON;
	}
	  
      werror("Data on closed or non-existant channel %d\n",
	     channel_number);
      lsh_string_free(data);
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);
  
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_extended_data(struct packet_handler *c,
				    struct ssh_connection *connection UNUSED,
				    struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
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
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->receive
	  && !(channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      wwrite("Ignoring extended data on channel which is closing\n");
	      return LSH_OK | LSH_GOON;
	    }
	  else
	    {
	      int res = 0;
	      
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  wwrite("Channel extended data overflow. "
			 "Extra data ignored.\n");
		  data->length = channel->rec_window_size;
		}
	      
	      channel->rec_window_size -= data->length;

	      if (channel->rec_window_size < channel->max_window / 2)
		{
		  res = A_WRITE(channel->write, prepare_window_adjust
				(channel,
				 channel->max_window - channel->rec_window_size));
		  if (LSH_CLOSEDP(res))
		    return res;
		}

	      switch(type)
		{
		case SSH_EXTENDED_DATA_STDERR:
		  return channel_process_status(
		    closure->table, channel_number,
		    res | CHANNEL_RECEIVE(channel, 
					  CHANNEL_STDERR_DATA, data));
		default:
		  werror("Unknown type %d of extended data.\n",
			 type);
		  lsh_string_free(data);
		  return LSH_FAIL | LSH_DIE;
		}
	    }
	}
      werror("Extended data on closed or non-existant channel %d\n",
	     channel_number);
      lsh_string_free(data);
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);
  
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_eof(struct packet_handler *c,
			  struct ssh_connection *connection UNUSED,
			  struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_EOF)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);

      if (channel)
	{
	  int res = 0;
	  
	  if (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_RECEIVED_CLOSE))
	    {
	      wwrite("Receiving EOF on channel on closed channel.\n");
	      return LSH_FAIL | LSH_DIE;
	    }

	  channel->flags |= CHANNEL_RECEIVED_EOF;

	  if (channel->eof)
	    res = CHANNEL_EOF(channel);
	  else
	    /* FIXME: What is a reasonable default behaviour?
	     * Closing the channel may be the right thing to do. */
	    if (! (channel->flags & CHANNEL_SENT_CLOSE))
	      res |= channel_close(channel);
#if 0
	  if (!LSH_CLOSEDP(res)
	      && ! (channel->flags & CHANNEL_SENT_CLOSE)
	      && (channel->flags & CHANNEL_SENT_EOF))
	    {
	      /* Both parties have sent EOF. Initiate close, if we
	       * havn't done that already. */
	      
	      res |= channel_close(channel);
	    }
#endif      
	  return channel_process_status(closure->table, channel_number,
					res);

	}
      werror("EOF on non-existant channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
    }
      
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_close(struct packet_handler *c,
			    struct ssh_connection *connection UNUSED,
			    struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_CLOSE)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  int res = 0;
	  
	  if (channel->flags & CHANNEL_RECEIVED_CLOSE)
	    {
	      wwrite("Receiving multiple CLOSE on channel.\n");
	      return LSH_FAIL | LSH_DIE;
	    }

	  channel->flags |= CHANNEL_RECEIVED_CLOSE;
	  
	  if (! (channel->flags & (CHANNEL_RECEIVED_EOF | CHANNEL_SENT_EOF)))
	    {
	      wwrite("Unexpected channel CLOSE.\n");
	    }

	  if (! (channel->flags & (CHANNEL_RECEIVED_EOF))
	      && channel->eof)
	    res = CHANNEL_EOF(channel);
	  
	  return channel_process_status(
	    closure->table, channel_number,
	    ( ( (channel->flags & (CHANNEL_SENT_CLOSE))
		? LSH_OK | LSH_CHANNEL_FINISHED
		: channel_close(channel))
	      | res));
	}
      werror("CLOSE on non-existant channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
      
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_open_confirm(struct packet_handler *c,
			      struct ssh_connection *connection UNUSED,
			      struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
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
      struct ssh_channel *channel = lookup_channel(closure->table,
						   local_channel_number);

      lsh_string_free(packet);

      if (channel && channel->open_confirm)
	{
	  channel->channel_number = remote_channel_number;
	  channel->send_window_size = window_size;
	  channel->send_max_packet = max_packet;

	  return channel_process_status(closure->table, local_channel_number,
					CHANNEL_OPEN_CONFIRM(channel));
	}
      werror("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel %d\n",
	     local_channel_number);
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_open_failure(struct packet_handler *c,
			      struct ssh_connection *connection UNUSED,
			      struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
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
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      /* lsh_string_free(packet); */

      if (channel && channel->open_failure)
	{
	  int res = CHANNEL_OPEN_FAILURE(channel);

	  lsh_string_free(packet);

	  return channel_process_status(closure->table, channel_number,
					res | LSH_CHANNEL_FINISHED);
	}
      werror("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE on channel %d\n",
	     channel_number);
      lsh_string_free(packet);
      
      return LSH_FAIL | LSH_DIE;
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_success(struct packet_handler *c,
			      struct ssh_connection *connection UNUSED,
			      struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_SUCCESS)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->channel_success)
	return channel_process_status(closure->table, channel_number,
				      CHANNEL_SUCCESS(channel));
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_failure(struct packet_handler *c,
			      struct ssh_connection *connection UNUSED,
			      struct lsh_string *packet)
{
  CAST(channel_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_FAILURE)
      && parse_uint32(&buffer, &channel_number)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->channel_failure)
	return channel_process_status(closure->table, channel_number,
				      CHANNEL_FAILURE(channel));
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int init_connection_service(struct ssh_service *s,
				   struct ssh_connection *connection)
{
  CAST(connection_service, self, s);

  struct channel_table *table;
  
  NEW(global_request_handler, globals);
  NEW(channel_open_handler, open);
  NEW(channel_handler, request);

  NEW(channel_handler, adjust);
  NEW(channel_handler, data);
  NEW(channel_handler, extended);

  NEW(channel_handler, eof);
  NEW(channel_handler, close);

  NEW(channel_handler, open_confirm);
  NEW(channel_handler, open_failure);

  NEW(channel_handler, channel_success);
  NEW(channel_handler, channel_failure);

  table = make_channel_table();
  
  globals->super.super.handler = do_global_request;
  globals->super.table = table;
  globals->global_requests = self->global_requests;
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = &globals->super.super;
    
  open->super.super.handler = do_channel_open;
  open->super.table = table;
  open->channel_types = self->channel_types;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = &open->super.super;

  request->super.handler = do_channel_request;
  request->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = &request->super;
  
  adjust->super.handler = do_window_adjust;
  adjust->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &adjust->super;

  data->super.handler = do_channel_data;
  data->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = &data->super;

  extended->super.handler = do_channel_extended_data;
  extended->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_EXTENDED_DATA] = &extended->super;

  eof->super.handler = do_channel_eof;
  eof->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = &eof->super;

  close->super.handler = do_channel_close;
  close->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = &close->super;

  open_confirm->super.handler = do_channel_open_confirm;
  open_confirm->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = &open_confirm->super;

  open_failure->super.handler = do_channel_open_failure;
  open_failure->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = &open_failure->super;
  
  channel_success->super.handler = do_channel_success;
  channel_success->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = &channel_success->super;

  channel_failure->super.handler = do_channel_failure;
  channel_failure->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_FAILURE] = &channel_failure->super;
    
  return self->start
    ? CONNECTION_START(self->start, table, connection->write)
    : LSH_OK | LSH_GOON;
}

struct ssh_service *make_connection_service(struct alist *global_requests,
					    struct alist *channel_types,
					    struct connection_startup *start)
{
  NEW(connection_service, self);

  self->super.init = init_connection_service;
  self->global_requests = global_requests;
  self->channel_types = channel_types;
  self->start = start;
  
  return &self->super;
}

struct lsh_string *format_channel_close(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_CLOSE,
		    channel->channel_number);
}

int channel_close(struct ssh_channel *channel)
{
  assert(! (channel->flags & CHANNEL_SENT_CLOSE));
  
  channel->flags |= CHANNEL_SENT_CLOSE;

  return A_WRITE(channel->write, format_channel_close(channel))
    | ( (channel->flags & CHANNEL_RECEIVED_CLOSE)
	? LSH_CHANNEL_FINISHED : 0);
}

struct lsh_string *format_channel_eof(struct ssh_channel *channel)
{
  return ssh_format("%c%i",
		    SSH_MSG_CHANNEL_EOF,
		    channel->channel_number);
}

int channel_eof(struct ssh_channel *channel)
{
  int res ;

  assert(! (channel->flags & CHANNEL_SENT_EOF));
  
  channel->flags |= CHANNEL_SENT_EOF;
  res = A_WRITE(channel->write, format_channel_eof(channel));

  if (LSH_CLOSEDP(res))
    return res;

  if ( (channel->flags & CHANNEL_CLOSE_AT_EOF)
       && (channel->flags & CHANNEL_RECEIVED_EOF))
    {
      /* Initiate close */
      res |= channel_close(channel);
    }

  return res;
}

void init_channel(struct ssh_channel *channel)
{
  /* channel->super.handler = do_read_channel; */
  channel->write = NULL;

  channel->flags = 0;
  channel->sources = 0;
  
  channel->request_types = NULL;
  channel->receive = NULL;
  channel->send = NULL;

  channel->close = NULL;
  channel->eof = NULL;

  channel->open_confirm = NULL;
  channel->open_failure = NULL;
  channel->channel_success = NULL;
  channel->channel_failure = NULL;
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
/* CLASS:
   (class
     (name channel_write)
     (super abstract_write)
     (vars
       (channel object ssh_channel)))
*/

/* CLASS:
   (class
     (name channel_write_extended)
     (super channel_write)
     (vars
       (type simple UINT32)))
*/

static int do_channel_write(struct abstract_write *w,
			    struct lsh_string *packet)
{
  struct channel_write *closure = (struct channel_write *) w;

  return A_WRITE(closure->channel->write,
		 channel_transmit_data(closure->channel, packet));
}

static int do_channel_write_extended(struct abstract_write *w,
				     struct lsh_string *packet)
{
  CAST(channel_write_extended, closure, w);

  return A_WRITE(closure->super.channel->write,
		 channel_transmit_extended(closure->super.channel,
					   closure->type,
					   packet));
}

struct abstract_write *make_channel_write(struct ssh_channel *channel)
{
  NEW(channel_write, closure);

  closure->super.write = do_channel_write;
  closure->channel = channel;

  return &closure->super;
}

struct abstract_write *make_channel_write_extended(struct ssh_channel *channel,
						   UINT32 type)
{
  NEW(channel_write_extended, closure);

  closure->super.super.write = do_channel_write_extended;
  closure->super.channel = channel;
  closure->type = type;
  
  return &closure->super.super;
}

struct read_handler *make_channel_read_data(struct ssh_channel *channel)
{
  return make_read_data(channel, make_channel_write(channel));
}

struct read_handler *make_channel_read_stderr(struct ssh_channel *channel)
{
  return make_read_data(channel,
			make_channel_write_extended(channel,
						    SSH_EXTENDED_DATA_STDERR));
}    

/* CLASS:
   (class
     (name channel_close_callback)
     (super close_callback)
     (vars
       (channel object ssh_channel)))
*/

/* Close callback for files we are writing to. */
static int channel_close_callback(struct close_callback *c, int reason)
{
  CAST(channel_close_callback, closure, c);

  switch (reason)
    {
    case CLOSE_EOF:
      /* Expected close: Do nothing */
      debug("channel_close_callback: Closing after EOF.\n");
      break;
    case CLOSE_WRITE_FAILED:
    case CLOSE_BROKEN_PIPE:
      channel_close(closure->channel);
      break;
    default:
      fatal("channel_close_callback: Unexpected close reason %d!\n",
	    reason);
    }
  /* FIXME: So far, the returned value is ignored. */
  return 17;
}
  
struct close_callback *make_channel_close(struct ssh_channel *channel)
{
  NEW(channel_close_callback, closure);
  
  closure->super.f = channel_close_callback;
  closure->channel = channel;

  return &closure->super;
}

struct lsh_string *prepare_channel_open(struct channel_table *table,
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

  index = register_channel(table, channel);
  if (index < 0)
    return NULL;

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
		   
struct lsh_string *format_channel_request(int type, struct ssh_channel *channel,
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
  
