/* connection.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "connection.h"

#include "command.h"
#include "compress.h"
#include "debug.h"
#include "encrypt.h"
#include "exception.h"
#include "format.h"
#include "io.h"
#include "keyexchange.h"
#include "pad.h"
#include "parse.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "connection.h.x"
#undef GABA_DEFINE

#include "connection.c.x"

const char *packet_types[0x100] =
#include "packet_types.h"
;

static void
connection_handle_packet(struct ssh_connection *closure,
			 struct lsh_string *packet)
{
  UINT8 msg;

  assert(!closure->paused);
  
  if (!packet->length)
    {
      werror("connection.c: Received empty packet!\n");
      PROTOCOL_ERROR(closure->e, "Received empty packet.");
      lsh_string_free(packet);
      return;
    }

  if (packet->length > closure->rec_max_packet)
    {
      werror("connection.c: Packet too large!\n");
      PROTOCOL_ERROR(closure->e, "Packet too large");
      lsh_string_free(packet);
      return;
    }
    
  msg = packet->data[0];

  debug("handle_connection: Received packet of type %i (%z)\n",
	msg, packet_types[msg]);
  
  switch(closure->read_kex_state)
    {
    case KEX_STATE_INIT:
      if (msg == SSH_MSG_NEWKEYS)
	{
	  werror("Unexpected NEWKEYS message!\n");
	  PROTOCOL_ERROR(closure->e, "Unexpected NEWKEYS message!");
	  lsh_string_free(packet);
	  return;
	}
      break;
    case KEX_STATE_IGNORE:
      debug("handle_connection: Ignoring packet %i\n", msg);

      /* It's conceivable with key exchange methods for which one
       * wants to switch to the NEWKEYS state immediately. But for
       * now, we always switch to the IN_PROGRESS state, to wait for a
       * KEXDH_INIT or KEXDH_REPLY message. */
      closure->read_kex_state = KEX_STATE_IN_PROGRESS;
      lsh_string_free(packet);
      return;

    case KEX_STATE_IN_PROGRESS:
      switch (msg)
	{
	case SSH_MSG_IGNORE:
	case SSH_MSG_DEBUG:
	case SSH_MSG_DISCONNECT:
	  /* These message types are allowed */
	  break;
	default:
	  if ( (msg < SSH_FIRST_KEYEXCHANGE_SPECIFIC)
	       || (msg >= SSH_FIRST_USERAUTH_GENERIC) )
	    {
	      /* Disallowed messages */
	    case SSH_MSG_NEWKEYS:
	    case SSH_MSG_KEXINIT:
	      {
		werror("Unexpected message of type %i (%z)!\n",
		       msg, packet_types[msg]);
		
		PROTOCOL_ERROR(closure->e,
			       "Unexpected message during key exchange");
		lsh_string_free(packet);
		return;
	      }
	    }
	}
      break;
    case KEX_STATE_NEWKEYS:
      switch(msg)
	{
	case SSH_MSG_NEWKEYS:
	case SSH_MSG_DISCONNECT:
	case SSH_MSG_IGNORE:
	case SSH_MSG_DEBUG:
	  /* Allowed */
	  break;
	default:
	  werror("Expected NEWKEYS message, but received message %i (%z)!\n",
		 msg, packet_types[msg]);
	  PROTOCOL_ERROR(closure->e, "Expected NEWKEYS message");
	  lsh_string_free(packet);
	  return;
	}
      break;
    default:
      fatal("handle_connection: Internal error.\n");
    }

  HANDLE_PACKET(closure->dispatch[msg], closure, packet);
  lsh_string_free(packet);
}

static void
connection_handle_pending(struct ssh_connection *self)
{
  while (!self->paused && !string_queue_is_empty(&self->pending))
    connection_handle_packet(self, string_queue_remove_head(&self->pending));
}

/* Deal with pausing of the connection. */
static void
do_handle_connection(struct abstract_write *w,
		     struct lsh_string *packet)
{
  CAST(ssh_connection, self, w);

  if (self->paused)
    string_queue_add_tail(&self->pending, packet);

  else if (string_queue_is_empty(&self->pending))
    connection_handle_packet(self, packet);

  else
    {
      string_queue_add_tail(&self->pending, packet);
      connection_handle_pending(self);
    }
}

DEFINE_PACKET_HANDLER(, connection_ignore_handler,
                      connection UNUSED, packet UNUSED)
{
}

DEFINE_PACKET_HANDLER(, connection_fail_handler, connection, packet UNUSED)
{
  PROTOCOL_ERROR(connection->e, NULL);
}

DEFINE_PACKET_HANDLER(, connection_unimplemented_handler, connection, packet)
{
  werror("Received packet of unimplemented type %i.\n",
	 packet->data[0]);

  C_WRITE(connection,
	  ssh_format("%c%i",
		     SSH_MSG_UNIMPLEMENTED,
		     packet->sequence_number));
}

DEFINE_PACKET_HANDLER(, connection_forward_handler, connection, packet)
{
  assert(connection->chain);
  /* FIXME: Packets of certain types (IGNORE, DEBUG, DISCONNECT)
   * could be sent with C_WRITE_NOW. */
  C_WRITE(connection->chain, packet);
}

DEFINE_PACKET_HANDLER(, connection_disconnect_handler, connection, packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 reason;

  UINT32 length;
  const UINT8 *msg;

  const UINT8 *language;
  UINT32 language_length;
  
  static const struct exception disconnect_exception =
    STATIC_EXCEPTION(EXC_FINISH_IO, "Received disconnect message.");
    
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_DISCONNECT)
      && (parse_uint32(&buffer, &reason))
      && (parse_string(&buffer, &length, &msg))
      && (parse_string(&buffer, &language_length, &language))
      && parse_eod(&buffer))
    {
      /* FIXME: Display a better message */
      werror("Disconnect for reason %i: %ups\n", reason, length, msg);
    }
  else
    werror("Invalid disconnect message!\n");
  
  EXCEPTION_RAISE(connection->e, &disconnect_exception);
}
     
/* GABA:
   (class
     (name exc_connection_handler)
     (super exception_handler)
     (vars
       (backend object io_backend)
       (connection object ssh_connection)))
*/

static struct lsh_string *
format_disconnect(int code, const char *msg, 
		  const char *language)
{
  return ssh_format("%c%i%z%z",
		    SSH_MSG_DISCONNECT,
		    code,
		    msg, language);
}

static void
do_exc_connection_handler(struct exception_handler *s,
			  const struct exception *e)
{
  CAST(exc_connection_handler, self, s);

  switch (e->type)
    {
    case EXC_PROTOCOL:
      {
	CAST_SUBTYPE(protocol_exception, exc, e);

        werror("Protocol error: %z\n", e->msg);
        
	if (exc->reason)
	  C_WRITE_NOW(self->connection,
		      format_disconnect(exc->reason, exc->super.msg, ""));
	
	EXCEPTION_RAISE(self->super.parent, &finish_read_exception);
      }
      break;

    case EXC_PAUSE_CONNECTION:
      assert(!self->connection->paused);
      self->connection->paused = 1;
      EXCEPTION_RAISE(self->super.parent,
		      make_simple_exception(EXC_PAUSE_READ, "locking connection."));
      break;

    case EXC_PAUSE_START_CONNECTION:
      /* NOTE: Raising EXC_PAUSE_START_READ will not by itself make
       * the connection start processing pending packets. Not until
       * the peer sends us more data.
       *
       * So any code that raises EXC_PAUSE_START_CONNECTION should
       * also call connection_handle_pending at a safe place. We
       * can't call it here, as we may be in the middle of the
       * handling of a packet. Installing a callout would be best. */
      
      assert(self->connection->paused);
      EXCEPTION_RAISE(self->super.parent,
		      make_simple_exception(EXC_PAUSE_START_READ, "unlocking connection."));
      
      self->connection->paused = 0;

      break;

    case EXC_FINISH_READ:
      /* FIXME: We could check if there are any channels still open,
       * and write a warning message if there are. */

      /* Fall through */
    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }
}

static struct exception_handler *
make_exc_connection_handler(struct ssh_connection *connection,
			  struct exception_handler *parent,
			  const char *context)
{
  NEW(exc_connection_handler, self);

  self->super.parent = parent;
  self->super.raise = do_exc_connection_handler;
  self->super.context = context;
  
  self->connection = connection;

  return &self->super;
}

struct ssh_connection *
make_ssh_connection(enum connection_flag flags,
		    struct address_info *peer,
		    struct address_info *local,
		    const char *debug_comment,
		    struct exception_handler *e)
{
  int i;

  NEW(ssh_connection, connection);

  connection->flags = flags;
  connection->peer = peer;
  connection->local = local;
  
  connection->debug_comment = debug_comment;
  connection->super.write = do_handle_connection;

  /* Exception handler that sends a proper disconnect message on
   * protocol errors */
  connection->e = make_exc_connection_handler(connection, e, HANDLER_CONTEXT);

  connection->keyexchange_done = NULL;
  
  /* Initialize instance variables */

  connection->versions[CONNECTION_SERVER]
    = connection->versions[CONNECTION_CLIENT]
    = connection->session_id = NULL;

  connection->peer_flags = 0;

  connection->timer = NULL;
  connection->user = NULL;
  
  connection->resources = make_resource_list();
  
  connection->rec_max_packet = SSH_MAX_PACKET;

  /* Initial encryption state */
  connection->kexinit = NULL;
  
  connection->send_crypto = connection->rec_crypto = NULL;
  connection->send_mac = connection->rec_mac = NULL;
  connection->send_compress = connection->rec_compress = NULL;
  
  connection->paused = 0;
  string_queue_init(&connection->pending);
  
  connection->read_kex_state = KEX_STATE_INIT;

  connection->key_expire = NULL;
  connection->sent_data = 0;

  connection->send_kex_only = 0;
  string_queue_init(&connection->send_queue);
  
  connection->kexinits[CONNECTION_CLIENT]
    = connection->kexinits[CONNECTION_SERVER] = NULL;

  connection->literal_kexinits[CONNECTION_CLIENT]
    = connection->literal_kexinits[CONNECTION_SERVER] = NULL;
  
  for (i = 0; i < 0x100; i++)
    connection->dispatch[i] = &connection_unimplemented_handler;

  connection->dispatch[0] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_DISCONNECT] = &connection_disconnect_handler;
  connection->dispatch[SSH_MSG_IGNORE] = &connection_ignore_handler;

  /* So far, all messages we send have to be supported. */ 
  connection->dispatch[SSH_MSG_UNIMPLEMENTED] = &connection_fail_handler;

  connection->dispatch[SSH_MSG_DEBUG] = &connection_debug_handler;

  /* Make all other known message types terminate the connection */

  connection->dispatch[SSH_MSG_SERVICE_REQUEST] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_NEWKEYS] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_BANNER] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_PK_OK] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_USERAUTH_PASSWD_CHANGEREQ] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_REQUEST_SUCCESS] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_REQUEST_FAILURE] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_EXTENDED_DATA] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = &connection_fail_handler;
  connection->dispatch[SSH_MSG_CHANNEL_FAILURE] = &connection_fail_handler;
  
  return connection;
}

void
connection_init_io(struct ssh_connection *connection,
		   struct abstract_write *raw,
		   struct randomness *r)
{
  /* Initialize i/o hooks */
  connection->raw = raw;
  connection->write_packet =
    make_packet_debug(
      make_packet_deflate(
	make_packet_pad(
	  make_packet_encrypt(raw, connection), 
	  connection,
	  r),
	connection),
      (connection->debug_comment
       ? ssh_format("%lz sent", connection->debug_comment)
       : ssh_format("Sent")));
}

void
connection_after_keyexchange(struct ssh_connection *self,
			     struct command_continuation *c)
{
  assert(!self->keyexchange_done);
  self->keyexchange_done = c;
}

/* GABA:
   (class
     (name connection_close_handler)
     (super lsh_callback)
     (vars
       (connection object ssh_connection)))
*/

static void
connection_die(struct lsh_callback *c)
{
  CAST(connection_close_handler, closure, c);
  
  verbose("Connection died.\n");
  
  KILL_RESOURCE_LIST(closure->connection->resources);
}

struct lsh_callback *
make_connection_close_handler(struct ssh_connection *c)
{
  NEW(connection_close_handler, closure);

  closure->connection = c;  
  closure->super.f = connection_die;

  return &closure->super;
}


/* Sending ordinary (non keyexchange) packets */
void
connection_send(struct ssh_connection *self,
		struct lsh_string *message)
{
  /* FIXME: Constify? Then we need to constify the string queue as
   * well. */
  if (self->send_kex_only)
    string_queue_add_tail(&self->send_queue, message);
  else
    {
      assert(string_queue_is_empty(&self->send_queue));
      C_WRITE_NOW(self, message);
    }
}

void
connection_send_kex_start(struct ssh_connection *self)
{
  assert(!self->send_kex_only);
  assert(string_queue_is_empty(&self->send_queue));
  self->send_kex_only = 1;
}

void
connection_send_kex_end(struct ssh_connection *self)
{
  assert(self->send_kex_only);

  while (!string_queue_is_empty(&self->send_queue))
    C_WRITE_NOW(self, string_queue_remove_head(&self->send_queue));

  self->send_kex_only = 0;

  if (self->keyexchange_done)
    {
      struct command_continuation *c = self->keyexchange_done;
      self->keyexchange_done = NULL;
  
      COMMAND_RETURN(c, self);
    }
}

/* Serialization. */

void connection_lock(struct ssh_connection *self)
{
  const struct exception pause
    = STATIC_EXCEPTION(EXC_PAUSE_CONNECTION, "locking connection.");
    
  EXCEPTION_RAISE(self->e, &pause);
}

void connection_unlock(struct ssh_connection *self)
{
  const struct exception unpause
    = STATIC_EXCEPTION(EXC_PAUSE_START_CONNECTION, "unlocking connection.");
    
  EXCEPTION_RAISE(self->e, &unpause);
}


/* Timeouts */
/* GABA:
   (class
     (name connection_timeout)
     (super lsh_callback)
     (vars
       (connection object ssh_connection)
       (e const object exception)))
*/

static void
do_connection_timeout(struct lsh_callback *s)
{
  CAST(connection_timeout, self, s);
  EXCEPTION_RAISE(self->connection->e, self->e);
}

void
connection_clear_timeout(struct ssh_connection *connection)
{
  if (connection->timer)
    {
      KILL_RESOURCE(connection->timer);
      connection->timer = NULL;
    }
}

void
connection_set_timeout(struct ssh_connection *connection,
		       unsigned seconds,
		       const char *msg)
{
  NEW(connection_timeout, timeout);
  timeout->super.f = do_connection_timeout;
  timeout->connection = connection;
  timeout->e = make_protocol_exception(0, msg);

  connection_clear_timeout(connection);
  
  connection->timer = io_callout(&timeout->super,
				 seconds);
  remember_resource(connection->resources, connection->timer);
}
