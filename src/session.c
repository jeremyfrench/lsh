/* session.c
 *
 */

#include "session.h"

#include <assert.h>

#include "service.h"

struct connection_service
{
  struct ssh_service super;

  /* Supported global requests */
  struct alist *global_requests;
  struct alist *channel_requests;
};

struct session_handler
{
  struct packet_handler super;
  
  struct ssh_session *session;
};

struct global_request_handler
{
  struct session_handler super;
  
  struct alist *global_requests;
};

struct channel_open_handler
{
  struct session_handler *super;

  struct alist *channel_types;
};

#if 0
struct channel_request_handler
{
  struct session_handler *super;

  struct alist *request_types;
};
#endif

/* Session objects */

#define INITIAL_CHANNELS 32
/* Arbitrary limit */
#define MAX_CHANNELS (1L<<17)

struct ssh_session *make_session()
{
  struct ssh_session *session;

  NEW(session);
  session->channels = xalloc(sizeof(struct ssh_channel *) * INITIAL_CHANNELS);
  session->allocated_channels = INITIAL_CHANNELS;
  session->next_channel = 0;
  session->used_channels = 0;
  session->max_channels = MAX_CHANNELS;
};

/* Returns -1 if allocation fails */
int alloc_channel(struct ssh_session *session)
{
  int i;
  for(i = session->next_channel; i < session->used_channels; i++)
    {
      if (!session->channels[i])
	{
	  session->next_channel = i+1;
	  return i;
	}
    }
  if (i == session->max_channels)
    return -1;
  if (i == session->allocated_channels) 
    {
      int new_size = session->allocated_channels * 2;
      struct ssh_channel **new
	= xalloc(sizeof(struct ssh_channel *) * new_size);

      memcpy(new, session->channels,
	     sizeof(struct ssh_channel *) * session->used_channels);
      
      session->channels = new;
      session->allocated_channels = new_size;
    }

  session->next_channel = session->used_channels = i+1;

  return i;
}

void dealloc_channel(struct ssh_session *session, int i)
{
  assert(i >= 0);
  assert(i < session->used_channels);
  
  session->channels[i] = NULL;

  if (i < session->next_channel)
    next_channel = i;
}

struct ssh_channel *lookup_channel(struct ssh_session *session, UINT32 i)
{
  return (i < session->used_channels)
    ? session->channels[i] : NULL;
}

/* Channel related messages */

static int do_global_request(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct global_request_handler *closure = (struct global_request_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  int name;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_GLOBAL_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_boolean(&buffer, &want_reply))
    {
      struct global_request *req;

      lsh_string_free(packet);
      
      if (!name || !(req = ALIST_GET(closure->global_request, name)))
	return A_WRITE(connection->write,
		       format_request_failure());

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
  UINT8 msg_number;
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
					   "Unknown channel type"));
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
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT32 channel_number;
  int type;
  int want_reply;

  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_REQUEST)
      && parse_uint32(&buffer, &channel_number)
      && parse_atom(&buffer, &type)
      && parse_boolean(&bufferm &want_reply))
    {
      struct ssh_channel *channel = lookup_channel(channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  struct channel_request *req;

	  if (!type || ! ( (req = ALIST_GET(channel->request_types, type)) ))
	    return A_WRITE(connection->write,
			   format_channel_request_failure(...));

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
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT32 channel_number;
  UINT32 size;

  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_WINDOW_ADJUST)
      && parse_uint32(&buffer, &size)
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(channel_number);

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
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT32 channel_number;
  struct lsh_string *data;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_DATA)
      && ( (data = parse_string_copy(&buffer)) )
      && parse_eod(&buffer))
    {
      struct ssh_channel *channel = lookup_channel(channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  if (!channel->recieve)
	    {
	      werror("Recieved data on closed channel\n");
	      lsh_string_free(data);
	      return LSH_FAIL | LSH_DIE;
	    }    
	  if (data->length > channel->rec_window_size)
	    {
	      /* Truncate data to fit window */
	      werror("Channel data overflow. Extra data ignored.\n"); */
	      data->length = channel->rec_window_size;
	    }
	  channel->rec_window_size -= data->length; 
	  return CHANNEL_RECIEVE(channel, connection->write,
				 CHANNEL_DATA, data);
	}
	  
      werror("Data on non-existant channel %d\n",
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
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
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
      struct ssh_channel *channel = lookup_channel(channel_number);

      lsh_string_free(packet);
      
      if (channel)
	{
	  if (!channel->recieve)
	    {
	      werror("Recieved data on closed channel\n");
	      lsh_string_free(data);
	      return LSH_FAIL | LSH_DIE;
	    }    
	  if (data->length > channel->rec_window_size)
	    {
	      /* Truncate data to fit window */
	      werror("Channel extended data overflow. "
		     "Extra data ignored.\n"); */
	      data->length = channel->rec_window_size;
	    }
	  channel->rec_window_size -= data->length;
	  switch(type)
	    {
	    case SSH_EXTENDED_DATA_STDERR:
	      return CHANNEL_RECIEVE(channel, , connection->write,
				     CHANNEL_DATA, data);
	    default:
	      werror("Unknown type %d of extended data.\n",
		     type);
	      lsh_string_free(data);
	      return LSH_FAIL | LSH_DIE;
	    }
	}
      werror("Extended data on non-existant channel %d\n",
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
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_EOF)
      && parse_eod(&buffer))
    {
      lsh_string_free(packet);
      return CHANNEL_CLOSE(channel, connection->write, CHANNEL_EOF);
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_channel_close(struct packet_handler *c,
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  struct session_handler *closure = (struct session_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT32 channel_number;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_CHANNEL_CLOSE)
      && parse_eod(&buffer))
    {
      lsh_string_free(packet);
      return CHANNEL_CLOSE(channel, connection->write, CHANNEL_CLOSE);
    }
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int init_session_service(struct ssh_service *s,
				struct ssh_connection *c)
{
  struct connection_service *self = (struct connection_service *) s;
  struct ssh_session *session;
  
  struct global_request_handler *globals;
  struct channel_open_handler *open;
  struct session_handler *request;
  struct session_handler *adjust;
  struct session_handler *data;
  struct session_handler *extended;
  struct session_handler *eof;
  struct session_handler *close;
  
  MDEBUG(self);

  session->session = make_session();
  
  NEW(globals);
  globals->super.super.handler = do_global_request;
  globals->super.session = session;
  globals->global_requests = self->global_requests;
  con->dispatch[SSH_MSG_GLOBAL_REQUEST] = &globals->super.super;
    
  NEW(open);
  open->super.super.handler = do_channel_open;
  open->super.session = session;
  open->channel_requests = self->channel_requests;
  con->dispatch[SSH_MSG_CHANNEL_OPEN] = &open->super.super;

  NEW(request);
  request->super.handler = do_channel_request;
  request->session = session;
  con->dispatch[SSH_MSG_CHANNEL_REQUEST] = &request->super;
  
  NEW(adjust);
  adjust->super.handler = do_window_adjust;
  adjust->session = session;
  con->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &adjust->super;

  NEW(data);
  data->super.handler = do_channel_data;
  data->session = session;
  con->dispatch[SSH_MSG_CHANNEL_DATA] = &data->super;

  NEW(extended);
  extended->super.handler = do_channel_extended_data;
  extended->session = session;
  con->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &extended->super;

  NEW(eof);
  eof->super.handler = do_channel_eof;
  eof->session = session;
  con->dispatch[SSH_MSG_CHANNEL_EOF] = &eof->super;

  NEW(close);
  close->super.handler = do_channel_close;
  close->session = session;
  con->dispatch[SSH_MSG_CHANNEL_CLOSE] = &close->super;

  return 1;
}

struct ssh_service make_session_service(struct alist *global_requests,
					struct alist *channel_requests)
{
  struct connection_service *self;

  NEW(self);
  self->super.init = init_session_service;
  self->global_requests = global_requests;
  self->channel_requests = channel_requests;

  return &self->super;
}
