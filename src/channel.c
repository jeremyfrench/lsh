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

struct connection_service
{
  struct ssh_service super;

  /* Supported global requests */
  struct alist *global_requests;
  struct alist *channel_types;

  /* Initialize connection (for instance, request channels to be opened
   * or services to be forwarded. */
  struct connection_startup *start;
};

struct channel_handler
{
  struct packet_handler super;
  
  struct channel_table *table;
};

struct global_request_handler
{
  struct channel_handler super;
  
  struct alist *global_requests;
};

struct channel_open_handler
{
  struct channel_handler super;

  struct alist *channel_types;
};

#if 0
struct channel_request_handler
{
  struct channel_handler *super;

  struct alist *request_types;
};
#endif

struct lsh_string *format_global_failure(void)
{
  return ssh_format("%c", SSH_MSG_REQUEST_FAILURE);
}

struct lsh_string *format_open_confirmation(struct ssh_channel *channel,
					    UINT32 channel_number,
					    char *format, ...)
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
				       char *msg, char *language)
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
  struct channel_table *table;

  NEW(table);
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
int alloc_channel(struct channel_table *table)
{
  int i;
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
  assert(i < table->used_channels);
  
  table->channels[i] = NULL;

  if (i < table->next_channel)
    table->next_channel = i;
}

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

static int channel_process_status(struct channel_table *table,
				  int channel,
				  int status)
{
  if (status & LSH_CHANNEL_PENDING_CLOSE)
    table->pending_close = 1;
  
  if (status & LSH_CHANNEL_FINISHED)
    {
      /* Clear this bit */
      status &= ~LSH_CHANNEL_FINISHED;
      
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
  struct global_request_handler *closure = (struct global_request_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  int name;
  int want_reply;
  
  MDEBUG(closure);

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

      return GLOBAL_REQUEST(req, want_reply, &buffer);
    }
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}

static int do_channel_open(struct packet_handler *c,
			   struct ssh_connection *connection,
			   struct lsh_string *packet)
{
  struct channel_open_handler *closure = (struct channel_open_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  int type;
  UINT32 remote_channel_number;
  UINT32 window_size;
  UINT32 max_packet;
  
  MDEBUG(closure);

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
      
      channel = CHANNEL_OPEN(open, &buffer, &error, &error_msg, &args);
      
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
	  werror("Could not allocate a channel number for pened channel!\n");
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
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  int type;
  int want_reply;

  MDEBUG(closure);

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
	       CHANNEL_REQUEST(req, channel, want_reply, &buffer));
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
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  UINT32 size;

  MDEBUG(closure);

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
	  && !(channel->flags & (CHANNEL_RECIEVED_EOF | CHANNEL_RECIEVED_CLOSE)))
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
			   struct ssh_connection *connection,
			   struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  struct lsh_string *data;
  
  MDEBUG(closure);

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
      
      if (channel && channel->recieve
	  && !(channel->flags & (CHANNEL_RECIEVED_EOF | CHANNEL_RECIEVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      werror("Ignoring data on channel which is closing\n");
	      return LSH_OK | LSH_GOON;
	    }
	  else
	    {
	      int res = 0;
	      
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel data overflow. Extra data ignored.\n"); 
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

	      return channel_process_status(
		closure->table, channel_number,
		res | CHANNEL_RECIEVE(channel, 
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
				    struct ssh_connection *connection,
				    struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  UINT32 type;
  struct lsh_string *data;
  
  MDEBUG(closure);

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
      
      if (channel && channel->recieve
	  && !(channel->flags & (CHANNEL_RECIEVED_EOF | CHANNEL_RECIEVED_CLOSE)))
	{
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    {
	      werror("Ignoring extended data on channel which is closing\n");
	      return LSH_OK | LSH_GOON;
	    }
	  else
	    {
	      int res = 0;
	      
	      if (data->length > channel->rec_window_size)
		{
		  /* Truncate data to fit window */
		  werror("Channel extended data overflow. "
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
		    res | CHANNEL_RECIEVE(channel, 
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
			  struct ssh_connection *connection,
			  struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

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
	  if (channel->flags & (CHANNEL_RECIEVED_EOF | CHANNEL_RECIEVED_CLOSE))
	    {
	      werror("Recieving EOF on channel on closed channel.\n");
	      return LSH_FAIL | LSH_DIE;
	    }

	  channel->flags |= CHANNEL_RECIEVED_EOF;
	  
	  if (channel->flags & CHANNEL_SENT_CLOSE)
	    /* Do nothing */
	    return LSH_OK | LSH_GOON;

	  if (channel->flags & CHANNEL_SENT_EOF)
	    {
	      /* Both parties have sent EOF. Initiate close, if we
	       * havn't done that already. */

	      if (channel->flags & CHANNEL_SENT_CLOSE)
		return LSH_OK | LSH_GOON;
	      else
		return channel_process_status(
		  closure->table, channel_number,
		  channel_close(channel));
	    }
	  return LSH_OK | LSH_GOON;
	}
      werror("EOF on non-existant channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
    }
      
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_close(struct packet_handler *c,
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

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
	  if (channel->flags & CHANNEL_RECIEVED_CLOSE)
	    {
	      werror("Recieving multiple CLOSE on channel.\n");
	      return LSH_FAIL | LSH_DIE;
	    }

	  channel->flags |= CHANNEL_RECIEVED_CLOSE;
	  
	  if (! (channel->flags & (CHANNEL_RECIEVED_EOF | CHANNEL_SENT_EOF)))
	    {
	      werror("Unexpected channel CLOSE.\n");
	    }
	  
	  return channel_process_status(
	    closure->table, channel_number,
	    ( (channel->flags & (CHANNEL_SENT_CLOSE))
	      ? LSH_OK | LSH_CHANNEL_FINISHED
	      : channel_close(channel)));
	}
      werror("CLOSE on non-existant channel %d\n",
	     channel_number);
      return LSH_FAIL | LSH_DIE;
      
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_open_confirm(struct packet_handler *c,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 local_channel_number;
  UINT32 remote_channel_number;  
  UINT32 window_size;
  UINT32 max_packet;
  
  MDEBUG(closure);

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
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  UINT32 reason;

  UINT8 *msg;
  UINT32 length;

  UINT8 *language;
  UINT32 language_length;
  
  MDEBUG(closure);

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
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

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
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct channel_handler *closure = (struct channel_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

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
  struct connection_service *self = (struct connection_service *) s;
  struct channel_table *table;
  
  struct global_request_handler *globals;
  struct channel_open_handler *open;
  struct channel_handler *request;

  struct channel_handler *adjust;
  struct channel_handler *data;
  struct channel_handler *extended;

  struct channel_handler *eof;
  struct channel_handler *close;

  struct channel_handler *open_confirm;
  struct channel_handler *open_failure;

  struct channel_handler *channel_success;
  struct channel_handler *channel_failure;

  MDEBUG(self);

  table = make_channel_table();
  
  NEW(globals);
  globals->super.super.handler = do_global_request;
  globals->super.table = table;
  globals->global_requests = self->global_requests;
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = &globals->super.super;
    
  NEW(open);
  open->super.super.handler = do_channel_open;
  open->super.table = table;
  open->channel_types = self->channel_types;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = &open->super.super;

  NEW(request);
  request->super.handler = do_channel_request;
  request->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = &request->super;
  
  NEW(adjust);
  adjust->super.handler = do_window_adjust;
  adjust->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &adjust->super;

  NEW(data);
  data->super.handler = do_channel_data;
  data->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = &data->super;

  NEW(extended);
  extended->super.handler = do_channel_extended_data;
  extended->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &extended->super;

  NEW(eof);
  eof->super.handler = do_channel_eof;
  eof->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = &eof->super;

  NEW(close);
  close->super.handler = do_channel_close;
  close->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = &close->super;

  NEW(open_confirm);
  open_confirm->super.handler = do_channel_open_confirm;
  open_confirm->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = &open_confirm->super;

  NEW(open_failure);
  open_failure->super.handler = do_channel_open_failure;
  open_failure->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = &open_failure->super;
  
  NEW(channel_success);
  channel_success->super.handler = do_channel_success;
  channel_success->table = table;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = &channel_success->super;

  NEW(channel_failure);
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
  struct connection_service *self;

  NEW(self);

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
  channel->flags |= CHANNEL_SENT_CLOSE;

  return A_WRITE(channel->write, format_channel_close(channel))
    | ( (channel->flags & CHANNEL_RECIEVED_CLOSE)
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
  
  channel->flags |= CHANNEL_SENT_EOF;
  res =  A_WRITE(channel->write, format_channel_eof(channel));

  if (LSH_CLOSEDP(res))
    return res;

  if (channel->flags & CHANNEL_RECIEVED_EOF)
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
  
  channel->request_types = NULL;
  channel->recieve = NULL;
  channel->send = NULL;
#if 0
  channel->close = NULL;
  channel->eof = NULL;
#endif
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
		    type,
		    channel->channel_number,
		    data);
}

/* Writing data to a channel */
struct channel_write
{
  struct abstract_write super;
  struct ssh_channel *channel;
};

struct channel_write_extended
{
  struct channel_write super;
  UINT32 type;
};

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
  struct channel_write_extended *closure = (struct channel_write_extended *) w;

  return A_WRITE(closure->super.channel->write,
		 channel_transmit_extended(closure->super.channel,
					   closure->type,
					   packet));
}

struct abstract_write *make_channel_write(struct ssh_channel *channel)
{
  struct channel_write *closure;

  NEW(closure);

  closure->super.write = do_channel_write;
  closure->channel = channel;

  return &closure->super;
}

struct abstract_write *make_channel_write_extended(struct ssh_channel *channel,
						   UINT32 type)
{
  struct channel_write_extended *closure;

  NEW(closure);

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

struct channel_close_callback
{
  struct close_callback super;
  struct ssh_channel *channel;
};

static int channel_close_callback(struct close_callback *c, int reason)
{
  struct channel_close_callback *closure = (struct channel_close_callback *)c;

  MDEBUG(closure);

  channel_close(closure->channel);

  /* FIXME: So far, the returned value is ignored. */
  return 17;
}
  
struct close_callback *make_channel_close(struct ssh_channel *channel)
{
  struct channel_close_callback *closure;

  NEW(closure);
  closure->super.f = channel_close_callback;
  closure->channel = channel;

  return &closure->super;
}

struct lsh_string *prepare_channel_open(struct channel_table *table,
					int type, struct ssh_channel *channel,
					char *format, ...)
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
					  int want_reply, char *format, ...)
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
  
