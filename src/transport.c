/* transport.c
 *
 * Interface for the ssh transport protocol.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "transport.h"

#define GABA_DEFINE
# include "transport.h.x"
#undef GABA_DEFINE

#include "transport.c.x"

/* Maximum time for keyexchange to complete */
#define TRANSPORT_TIMEOUT_KEYEXCHANGE (10 * 60)

/* Session key lifetime */
#define TRANSPORT_TIMEOUT_REEXCHANGE (40 * 60)

/* Time to wait for write buffer to drain after disconnect */
#define TRANSPORT_TIMEOUT_CLOSE (5 * 60)

static struct lsh_string *
format_newkeys(void)
{
  return ssh_format("%c", SSH_MSG_NEWKEYS);
}

void
init_transport_connection(struct transport_connection *self,
			  void (*kill)(struct resource *s),
			  struct transport_context *ctx,
			  int ssh_input, int ssh_output,
			  void (*event)(struct transport_connection *,
					enum transport_event event))
{
  init_resource(&self->super, kill);
  
  self->ctx = ctx;

  init_kexinit_state(&self->kex);
  self->session_id = NULL;
  self->keyexchange_handler = NULL;
  self->new_mac = NULL;
  self->new_crypto = NULL;
  self->new_inflate = NULL;

  self->expire = NULL;
  
  self->ssh_input = ssh_input;
  self->reader = make_transport_read_state();
  self->read_active = 0;
  
  /* One extra byte needed for inflate */
  self->read_packet = lsh_string_alloc(SSH_MAX_PACKET + 1);
  self->retry_length = 0;
  self->retry_seqno = 0;
  io_register_fd(ssh_input, "transport read fd");

  self->ssh_output = ssh_output;
  self->writer = make_transport_write_state();
  self->write_active = 0;
  self->write_margin = SSH_MAX_TRANSPORT_RESPONSE;
  if (ssh_output != ssh_input)
    io_register_fd(ssh_output, "transport write fd");

  self->closing = 0;
  self->event_handler = event;
}

/* GABA:
   (class
     (name transport_timeout)
     (super lsh_callback)
     (vars
       (connection object transport_connection)))
*/

static void
transport_timeout(struct transport_connection *connection,
		  unsigned seconds,
		  void (*callback)(struct lsh_callback *s))
{
  NEW(transport_timeout, self);
  self->super.f = callback;
  self->connection = connection;

  if (connection->expire)
    KILL_RESOURCE(connection->expire);

  connection->expire = io_callout(&self->super, seconds);
}

static void
transport_timeout_close(struct lsh_callback *s)
{
  CAST(transport_timeout, self, s);
  struct transport_connection *connection = self->connection;

  KILL_RESOURCE(&connection->super);
}

/* Intended to be called by the kill method in child class. */
void
transport_connection_kill(struct transport_connection *connection)
{
  if (connection->expire)
    {
      KILL_RESOURCE(connection->expire);
      connection->expire = NULL;
    }
      
  io_close_fd(connection->ssh_input);

  if (connection->ssh_output != connection->ssh_input)
    io_close_fd(connection->ssh_output);
  
  connection->ssh_input = connection->ssh_output = -1;
}

/* We close the connection when we either have sent a DISCONNECT
   message (possible as the result of a protocol error), or when we
   have received a DISCONNECT message. In the first case, we want to
   let our write buffer for the ssh connection drain (so that our
   DISCONNECT message is delivered properly).

   In both cases, the application can't generate any more data. We
   generate a TRANSPORT_EVENT_CLOSE event tell it, and the return
   value tells us if the application is finished.

   When a DISCONNECT message is sent and received, we stop caring
   about delivering application data. It's the job of the connection
   layer's channel close logic, with CHANNEL_EOF and CHANNEL_CLOSE to
   decide when the connection can be disconnected.
*/

void
transport_close(struct transport_connection *connection, int flush)
{
  trace("transport_close\n");

  if (connection->super.alive && !connection->closing)
    {
      connection->event_handler(connection, TRANSPORT_EVENT_CLOSE);

      if (connection->expire)
	{
	  KILL_RESOURCE(connection->expire);
	  connection->expire = NULL;
	}

      if (connection->ssh_input != connection->ssh_output)
	io_close_fd (connection->ssh_input);
      
      connection->ssh_input = -1;

      if (flush && connection->write_active)
	{
	  /* Stay open for a while, to allow buffers to drain. */
	  connection->closing = 1;

	  transport_timeout(connection,
			    TRANSPORT_TIMEOUT_CLOSE,
			    transport_timeout_close);
	  trace("transport_close: Waiting for buffers to drain.\n");
	}
      else
	{	      
	  io_close_fd(connection->ssh_output);
	  connection->ssh_output = -1;
	  KILL_RESOURCE(&connection->super);
	}
    }
}

void
transport_kexinit_handler(struct transport_connection *connection,
			  uint32_t length, const uint8_t *packet)
{
  int is_server = connection->ctx->is_server;
  const char *error;

  /* Have we sent a kexinit message already? */
  if (!connection->kex.kexinit[is_server])
    transport_send_kexinit(connection);
  
  error = handle_kexinit(&connection->kex, length, packet,
			 connection->ctx->algorithms,
			 is_server);

  if (error)
    {
      transport_disconnect(connection,
			   SSH_DISCONNECT_KEY_EXCHANGE_FAILED, error);
      return;
    }
  {
    CAST_SUBTYPE(keyexchange_algorithm, kex_algorithm,
		 LIST(connection->kex.algorithm_list)[KEX_KEY_EXCHANGE]);
    
    connection->keyexchange_handler
      = KEYEXCHANGE_INIT(kex_algorithm, connection);

    if (!connection->keyexchange_handler)
      transport_disconnect(connection,
			   SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			   "Configuration error");
  }  
}

static void
transport_timeout_reexchange(struct lsh_callback *s)
{
  CAST(transport_timeout, self, s);
  struct transport_connection *connection = self->connection;

  verbose("Session key expired. Initiating key re-exchange.\n");
  transport_send_kexinit(connection);
}

/* Returns 1 if processing of the packet is complete, or 0 if it
   should be retried later. */
static int
transport_process_packet(struct transport_connection *connection,
			 uint32_t seqno, uint32_t length, const struct lsh_string *packet)
{
  const uint8_t *data;
  uint8_t msg;

  if (length == 0)
    {
      transport_protocol_error(connection, "Received empty packet");
      return 1;
    }

  data = lsh_string_data(packet);
  msg = data[0];

  trace("transport_process_packet: %T (%i) message, length %i\n",
	msg, msg, length);
  
  /* Messages of type IGNORE, DISCONNECT and DEBUG are always
     acceptable. */
  if (msg == SSH_MSG_IGNORE)
    {
      /* Do nothing */
      /* FIXME: Better to pass it the application? */
    }
  else if (msg == SSH_MSG_DISCONNECT)
    {
      verbose("Received disconnect message.\n");
      transport_close(connection, 0);
    }
  else if (msg == SSH_MSG_DEBUG)
    {
      /* Ignore it. Perhaps it's best to pass it on to the
	 application? */
    }

  /* Otherwise, behaviour depends on the kex state */
  else switch (connection->kex.read_state)
    {
    default:
      abort();
    case KEX_STATE_IGNORE:
      connection->kex.read_state = KEX_STATE_IN_PROGRESS;
      break;
    case KEX_STATE_IN_PROGRESS:
      if (msg < SSH_FIRST_KEYEXCHANGE_SPECIFIC
	  || msg >= SSH_FIRST_USERAUTH_GENERIC)
	{
	  werror("Unexpected %T (%i) message during key exchange.\n", msg, msg);
	  transport_protocol_error(connection,
				   "Unexpected message during key exchange");
	}
      else
	connection->keyexchange_handler->handler(connection->keyexchange_handler,
						 connection, length, data);
      break;
    case KEX_STATE_NEWKEYS:
      if (msg != SSH_MSG_NEWKEYS)
	transport_protocol_error(connection, "NEWKEYS expected");
      else if (length != 1)
	transport_protocol_error(connection, "Invalid NEWKEYS message");
      else
	{
	  transport_read_new_keys(connection->reader,
				  connection->new_mac,
				  connection->new_crypto,
				  connection->new_inflate);
	  connection->new_mac = NULL;
	  connection->new_crypto = NULL;
	  connection->new_inflate = NULL;

	  reset_kexinit_state(&connection->kex);
	  transport_timeout(connection,
			    TRANSPORT_TIMEOUT_REEXCHANGE,
			    transport_timeout_reexchange);	      
	}
      break;

    case KEX_STATE_INIT:
      if (msg == SSH_MSG_KEXINIT)
	transport_kexinit_handler(connection, length, data);
	  
      /* Pass on everything except keyexchagne related messages. */
      else if ( (msg < SSH_FIRST_KEYEXCHANGE_GENERIC
		 || msg >= SSH_FIRST_USERAUTH_GENERIC)
		&& connection->packet_handler)
	return connection->packet_handler(connection, seqno, length, data);
      else
	transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH,
			      format_unimplemented(seqno));
      break;
    }
  return 1;
}

static void *
oop_read_ssh(oop_source *source UNUSED,
	     int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(transport_connection, connection, (struct lsh_object *) state);
  int error;
  const char *error_msg;
  enum ssh_read_status status;

  assert(event == OOP_READ);
  assert(fd == connection->ssh_input);

  assert(!connection->retry_length);

  while (connection->line_handler && connection->ssh_input >= 0)
    {
      uint32_t length;
      const uint8_t *line;
  
      status = transport_read_line(connection->reader, fd, &error, &error_msg,
				   &length, &line);
      fd = -1;
      
      switch (status)
	{
	default:
	  return OOP_CONTINUE;

	case SSH_READ_IO_ERROR:
	  werror("Read error: %e\n", error);
	  transport_close(connection, 0);
	  break;

	case SSH_READ_PROTOCOL_ERROR:
	  transport_disconnect(connection, error, error_msg);
	  break;

	case SSH_READ_EOF:
	  werror("Unexpected EOF at start of line.\n");
	  transport_close(connection, 0);
	  break;

	case SSH_READ_COMPLETE:
	  connection->line_handler(connection, length, line);
	  break;
	}
    }
  while (connection->ssh_input >= 0)
    {
      uint32_t seqno;
      uint32_t length;
      
      status = transport_read_packet(connection->reader, fd, &error, &error_msg,
				     &seqno, &length, connection->read_packet);
      fd = -1;

      switch (status)
	{
	case SSH_READ_IO_ERROR:
	  werror("Read error: %e\n", error);
	  transport_close(connection, 0);
	  break;

	case SSH_READ_PROTOCOL_ERROR:
	  transport_disconnect(connection, error, error_msg);
	  break;

	case SSH_READ_EOF:
	  werror("Unexpected EOF at start of packet.\n");
	  transport_close(connection, 0);	  
	  break;

	case SSH_READ_PUSH:
	  connection->event_handler(connection, TRANSPORT_EVENT_PUSH);
	  /* Fall through */
	case SSH_READ_PENDING:
	  return OOP_CONTINUE;
	  
	case SSH_READ_COMPLETE:
	  if (!transport_process_packet(connection, seqno, length, connection->read_packet))
	    {
	      connection->retry_length = length;
	      connection->retry_seqno = seqno;
	      transport_stop_read(connection);
	      return OOP_CONTINUE;
	    }
	  break;
	}
    }
  return OOP_CONTINUE;
}

static void *
oop_timer_retry(oop_source *oop UNUSED,
		struct timeval tv UNUSED, void *state)
{
  CAST_SUBTYPE(transport_connection, connection, (struct lsh_object *) state);
  uint32_t length = connection->retry_length;
  uint32_t seqno = connection->retry_seqno;
  
  assert(length);

  connection->retry_length = 0;
  connection->retry_seqno = 0;
  connection->read_active = 0;

  if (!connection->packet_handler(connection, seqno, length,
				  lsh_string_data(connection->read_packet)))
    {
      transport_disconnect(connection,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Application layer not responsive.");
      return OOP_CONTINUE;
    }

  /* Process any remaining buffered packets */
  while (connection->ssh_input >= 0)
    {
      enum ssh_read_status status;
      const char *error_msg;
      int error;

      status = transport_read_packet(connection->reader, -1, &error, &error_msg,
				     &seqno, &length, connection->read_packet);

      switch (status)
	{
	case SSH_READ_IO_ERROR:
	  werror("Read error: %e\n", error);
	  transport_close(connection, 0);
	  break;

	case SSH_READ_PROTOCOL_ERROR:
	  transport_disconnect(connection, error, error_msg);
	  break;

	case SSH_READ_EOF:
	  werror("Unexpected EOF at start of packet.\n");
	  transport_close(connection, 0);	  
	  break;

	case SSH_READ_PUSH:
	  connection->event_handler(connection, TRANSPORT_EVENT_PUSH);
	  /* Fall through */
	case SSH_READ_PENDING:
	  transport_start_read(connection);
	  return OOP_CONTINUE;
	  
	case SSH_READ_COMPLETE:
	  if (!transport_process_packet(connection, seqno, length, connection->read_packet))
	    {
	      connection->retry_length = length;
	      connection->retry_seqno = seqno;
	      /* Wait for application to wake us up again */
	      return OOP_CONTINUE;
	    }
	  break;
	}
    }
  return OOP_CONTINUE;
}

void
transport_start_read(struct transport_connection *connection)
{
  if (!connection->read_active)
    {
      connection->read_active = 1;

      if (connection->retry_length)
	/* Arrange to have the packet handler called from the main
	   event loop. */
	global_oop_source->on_time(global_oop_source,
				   OOP_TIME_NOW, oop_timer_retry, connection);
      else
	global_oop_source->on_fd(global_oop_source, connection->ssh_input,
				 OOP_READ, oop_read_ssh, connection);
    }
}

void
transport_stop_read(struct transport_connection *connection)
{
  connection->read_active = 0;
  global_oop_source->cancel_fd(global_oop_source,
			       connection->ssh_input, OOP_READ);  
}

/* Returns 1 if the write buffer is close to full */ 
static int
transport_write_almost_full(struct transport_connection *connection)
{
  return (connection->writer->super.length + connection->write_margin
	  > lsh_string_length(connection->writer->super.buffer));
}

static void
transport_stop_write(struct transport_connection *connection);

static void *
oop_write_ssh(oop_source *source UNUSED,
	      int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(transport_connection, connection, (struct lsh_object *) state);
  enum transport_write_status status;

  assert(event == OOP_WRITE);
  assert(fd == connection->ssh_output);

  status = transport_write_flush(connection->writer, fd, connection->ctx->random);
  switch(status)
    {
    default:
    case TRANSPORT_WRITE_OVERFLOW:
      abort();
    case TRANSPORT_WRITE_PENDING:
      /* More to write */
      break;
    case TRANSPORT_WRITE_COMPLETE:
      transport_stop_write(connection);
      break;
      
    case TRANSPORT_WRITE_IO_ERROR:
      if (errno != EWOULDBLOCK)
	{
	  werror("Write failed: %e\n", errno);
	  transport_close(connection, 0);
	}
      break;
    }
  return OOP_CONTINUE;
}

static void
transport_start_write(struct transport_connection *connection)
{
  if (!connection->write_active)
    {
      connection->write_active = 1;
      
      global_oop_source->on_fd(global_oop_source, connection->ssh_output,
			       OOP_WRITE, oop_write_ssh, connection);
    }
  
  if (connection->kex.write_state == KEX_STATE_INIT
      && transport_write_almost_full(connection))
    connection->event_handler(connection,
			      TRANSPORT_EVENT_STOP_APPLICATION);
}

static void
transport_stop_write(struct transport_connection *connection)
{
  if (connection->write_active)
    {
      connection->write_active = 0;

      global_oop_source->cancel_fd(global_oop_source,
				   connection->ssh_output, OOP_WRITE);
      if (connection->closing)
	{
	  close(connection->ssh_output);
	  connection->ssh_output = -1;

	  connection->closing--;
	  if(!connection->closing)
	    KILL_RESOURCE(&connection->super);
	}
      else if (connection->kex.write_state == KEX_STATE_INIT
	       && !transport_write_almost_full(connection))
	connection->event_handler(connection,
				  TRANSPORT_EVENT_START_APPLICATION); 
    }
}

/* FIXME: Naming is unfortunate, with transport_write_packet vs
   transport_send_packet.

   FIXME: Use a length / const uint8_t * interface.

   FIXME: Return a result code saying if more data can be sent right
   away, or if the buffer is full.
*/

/* A NULL packets means to push out the buffered data. */
void
transport_send_packet(struct transport_connection *connection,
		      enum transport_write_flag flags,
		      struct lsh_string *packet)
{
  struct transport_write_state *writer;
  enum transport_write_status status;

  if (!connection->super.alive)
    {
      werror("connection_write_data: Connection is dead.\n");
      lsh_string_free(packet);
      return;
    }

  writer = connection->writer;  
  if (packet)
    status = transport_write_packet(writer, connection->ssh_output,
				    flags, packet, connection->ctx->random);
  else
    status = transport_write_flush(writer, connection->ssh_output,
				   connection->ctx->random);
  switch (status)
    {
    case TRANSPORT_WRITE_OVERFLOW:
      werror("Remote peer not responsive. Disconnecting.\n");
      transport_close(connection, 0);
      break;
    case TRANSPORT_WRITE_IO_ERROR:
      werror("Write failed: %e\n", errno);
      transport_close(connection, 0);
      break;
    case TRANSPORT_WRITE_PENDING:
      transport_start_write(connection);
      break;
    case TRANSPORT_WRITE_COMPLETE:
      transport_stop_write(connection);
      break;
    }
}

void
transport_disconnect(struct transport_connection *connection,
		     int reason, const uint8_t *msg)
{
  if (msg)
    werror("Disconnecting: %z\n", msg);
  
  if (reason)
    transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH,
			  format_disconnect(reason, msg, ""));

  transport_close(connection, 1);
};

static void
transport_timeout_keyexchange(struct lsh_callback *s)
{
  CAST(transport_timeout, self, s);
  struct transport_connection *connection = self->connection;

  transport_disconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
		       "Key exchange timeout");  
}

void
transport_send_kexinit(struct transport_connection *connection)
{
  int is_server = connection->ctx->is_server;
  struct lsh_string *s;
  struct kexinit *kex;

  connection->kex.write_state = 1;

  if (connection->session_id)
    /* This is a reexchange; no more data can be sent */
    connection->event_handler(connection, TRANSPORT_EVENT_STOP_APPLICATION);
  
  kex = MAKE_KEXINIT(connection->ctx->kexinit, connection->ctx->random);
  connection->kex.kexinit[is_server] = kex;

  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.read_state == KEX_STATE_INIT);
  
  s = format_kexinit(kex);
  connection->kex.literal_kexinit[is_server] = lsh_string_dup(s); 
  transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH, s);

  /* NOTE: This feature isn't fully implemented, as we won't tell
   * the selected key exchange method if the guess was "right". */
  if (kex->first_kex_packet_follows)
    {
      s = kex->first_kex_packet;
      kex->first_kex_packet = NULL;

      transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH, s);
    }

  transport_timeout(connection,
		    TRANSPORT_TIMEOUT_KEYEXCHANGE,
		    transport_timeout_keyexchange);
}

void
transport_keyexchange_finish(struct transport_connection *connection,
			     const struct hash_algorithm *H,
			     struct lsh_string *exchange_hash,
			     struct lsh_string *K)
{
  int first = !connection->session_id;

  transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH, format_newkeys());

  if (first)
    connection->session_id = exchange_hash;

  if (!keyexchange_finish(connection, H, exchange_hash, K))
    {
      transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			   "Key exchange resulted in weak keys!");
      return;
    }

  assert(connection->kex.read_state == KEX_STATE_IN_PROGRESS);
  connection->kex.read_state = KEX_STATE_NEWKEYS;  
  connection->kex.write_state = 0;
  
  if (first)    
    connection->event_handler(connection,
			      TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE);
  else
    {
      lsh_string_free(exchange_hash);
      connection->event_handler(connection,
				TRANSPORT_EVENT_START_APPLICATION);
    }
}

void
transport_handshake(struct transport_connection *connection,
		    struct lsh_string *version,
		    void (*line_handler)
		      (struct transport_connection *connection,
		       uint32_t length,
		       const uint8_t *line))
{
  int is_server = connection->ctx->is_server;
  enum transport_write_status status;
  
  connection->kex.version[is_server] = version;
  status = transport_write_line(connection->writer,
				connection->ssh_output,
				ssh_format("%lS\r\n", version));

  if (status < 0)
    {
      werror("Writing version string failed: %e\n", errno);
      transport_close(connection, 0);
    }

  transport_send_kexinit(connection);

  connection->line_handler = line_handler;

  transport_start_read(connection);
}
