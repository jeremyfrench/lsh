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

struct lsh_string *format_open_failure(UINT32 channel, UINT32 reason,
				       char *msg, char *language)
{
  return ssh_format("%c%i%i%z%z", SSH_MSG_CHANNEL_OPEN_FAILURE,
		    channel, reason, msg, language);
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

struct channel_table *make_table()
{
  struct channel_table *table;

  NEW(table);
  table->channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				      * INITIAL_CHANNELS);
  table->allocated_channels = INITIAL_CHANNELS;
  table->next_channel = 0;
  table->used_channels = 0;
  table->max_channels = MAX_CHANNELS;

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
  UINT32 channel_number;
  UINT32 rec_window_size;
  UINT32 rec_max_packet;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_OPEN)
      && parse_atom(&buffer, &type)
      && parse_uint32(&buffer, &rec_window_size)
      && parse_uint32(&buffer, &rec_max_packet))
    {
      struct channel_open *open;

      lsh_string_free(packet);
      
      if (!type || !(open = ALIST_GET(closure->channel_types, type)))
	return A_WRITE(connection->write,
		       format_open_failure(channel_number,
					   SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
					   "Unknown channel type", ""));
      return CHANNEL_OPEN(open, channel_number, rec_window_size,
			  rec_max_packet, &buffer);
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

	  if (!type || ! ( (req = ALIST_GET(channel->request_types, type)) ))
	    return A_WRITE(connection->write,
			   format_channel_failure(channel->channel_number));

	  return CHANNEL_REQUEST(req, channel, want_reply, &buffer);
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
      && parse_uint32(&buffer, &size)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  channel->send_window_size += size;
	  return LSH_OK | LSH_GOON;
	}
      /* FIXME: What to do now? Should unknown channel numbers be
       * ignored silently? */
      werror("SSH_MSG_CHANNEL_WINDOW_ADJUST on nonexistant channel %d\n",
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
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->recieve)
	{
	  if (data->length > channel->rec_window_size)
	    {
	      /* Truncate data to fit window */
	      werror("Channel data overflow. Extra data ignored.\n"); 
	      data->length = channel->rec_window_size;
	    }
	  channel->rec_window_size -= data->length; 
	  return CHANNEL_RECIEVE(channel, connection->write,
				 CHANNEL_DATA, data);
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
      && parse_uint32(&buffer, &type)
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->recieve)
	{
	  if (data->length > channel->rec_window_size)
	    {
	      /* Truncate data to fit window */
	      werror("Channel extended data overflow. "
		     "Extra data ignored.\n");
	      data->length = channel->rec_window_size;
	    }
	  channel->rec_window_size -= data->length;
	  switch(type)
	    {
	    case SSH_EXTENDED_DATA_STDERR:
	      return CHANNEL_RECIEVE(channel, connection->write,
				     CHANNEL_DATA, data);
	    default:
	      werror("Unknown type %d of extended data.\n",
		     type);
	      lsh_string_free(data);
	      return LSH_FAIL | LSH_DIE;
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
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);

      if (channel && channel->eof)
	return CHANNEL_EOF(channel, connection->write);
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
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->close)
	return CHANNEL_CLOSE(channel, connection->write);
      
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

	  return CHANNEL_OPEN_CONFIRM(channel, connection->write);
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
	  int res = CHANNEL_OPEN_FAILURE(channel, connection->write);

	  lsh_string_free(packet);
	  dealloc_channel(closure->table, channel_number);
	  
	  return res;
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
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->success)
	return CHANNEL_SUCCESS(channel, connection->write);
      
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
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(closure->table,
						   channel_number);

      lsh_string_free(packet);
      
      if (channel && channel->failure)
	return CHANNEL_FAILURE(channel, connection->write);
      
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
    
  return closure->start
    ? CHANNEL_START(closure->start, table, connection->write)
    : LSH_OK | LSH_GOON;
}

struct lsh_string *channel_transmit_header(struct ssh_channel *channel,
					   struct abstract_write *write,
					   struct lsh_string *header,
					   struct lsh_string *data)
{
  UINT32 i;
  UINT32 left;
  UINT32 chunk = channel->send_max_packet;
  int res = 0;
  
  assert(data->length <= channel->send_window_size);

  if (data->length <= chunk)
    return A_WRITE(write, ssh_format("%lS%fS",
				     header,
				     data));

  for(i = 0, left = data->length;
      left; )
    {
      UINT32 size = MIN(chunk, left);
      
      res |= A_WRITE(write, ssh_format("%lS%s", header, 
				       size, data->data + i));
      if (LSH_CLOSEDP(res))
	break;

      i += size;
      left -= size;
    }

  lsh_string_free(data);
  return res;
}

struct lsh_string *channel_transmit(struct ssh_channel *channel,
				    struct abstract_write *write,
				    struct lsh_string *data)
{
  struct lsh_string *header = ssh_format("%c%i",
					 SSH_MSG_CHANNEL_DATA,
					 channel->channel_number);

  int res = channel_transmit_header(channel, header, write, data);

  lsh_string_free(header);

  return res;
}

struct lsh_string *channel_transmit_extended(struct ssh_channel *channel,
					     struct abstract_write *write,
					     UINT32 type,
					     struct lsh_string *data)
{
  struct lsh_string *header = ssh_format("%c%i%i",
					 SSH_MSG_CHANNEL_EXTENDED_DATA,
					 type,
					 channel->channel_number);
  
  int res = channel_transmit_header(channel, header, write, data);

  lsh_string_free(header);

  return res;
}


struct ssh_service *make_connection_service(struct alist *global_requests,
					    struct alist *channel_types)
{
  struct connection_service *self;

  NEW(self);

  self->super.init = init_connection_service;
  self->global_requests = global_requests;
  self->channel_types = channel_types;

  return &self->super;
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
  ssh_format_write(format, l2, packet->data+l1, args);
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
#define REQUEST_ARGS SSH_MSG_CHANNEL_REQUEST, channel->remote_channel_number \
  type, want_reply
    
  l1 = ssh_format_length(REQUEST_FORMAT, REQUEST_ARGS);
  
  va_start(args, format);
  l2 = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(l1 + l2);

  ssh_format_write(REQUEST_FORMAT, l1, packet->data, REQUEST_ARGS);

  va_start(args, format);
  ssh_format_write(format, l2, packet->data+l1, args);
  va_end(args);

  return packet;
#undef REQUEST_FORMAT
#undef REQUEST_ARGS
}
  
