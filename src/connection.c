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

#include "debug.h"
#include "encrypt.h"
#include "exception.h"
#include "format.h"
#include "disconnect.h"
#include "io.h"
#include "keyexchange.h"
#include "compress.h"
#include "packet_ignore.h"
#include "pad.h"
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
handle_connection(struct abstract_write *w,
		  struct lsh_string *packet)
{
  CAST(ssh_connection, closure, w);
  UINT8 msg;

  if (closure->busy)
    {
      werror("connection.c: Internal error: connection busy. Disconnecting!\n");
      EXCEPTION_RAISE(closure->e,
		      make_protocol_exception(SSH_DISCONNECT_BY_APPLICATION,
					      "Internal error."));
      return;
    }
  
  if (!packet->length)
    {
      werror("connection.c: Received empty packet!\n");
      PROTOCOL_ERROR(closure->e, "Received empty packet.");
      return;
    }

  if (packet->length > closure->rec_max_packet)
    {
      werror("connection.c: Packet too large!\n");
      PROTOCOL_ERROR(closure->e, "Packet too large");
      return;
    }
    
  msg = packet->data[0];

  debug("handle_connection: Received packet of type %i (%z)\n",
	msg, packet_types[msg]);
  
  switch(closure->kex_state)
    {
    case KEX_STATE_INIT:
      if (msg == SSH_MSG_NEWKEYS)
	{
	  werror("Unexpected NEWKEYS message!\n");
	  PROTOCOL_ERROR(closure->e, "Unexpected NEWKEYS message!");
	  return;
	}
      break;
    case KEX_STATE_IGNORE:
      debug("handle_connection: Ignoring packet %i\n", msg);

      /* It's conceivable with key exchange methods for which one
       * wants to switch to the NEWKEYS state immediately. But for
       * now, we always switch to the IN_PROGRESS state, to wait for a
       * KEXDH_INIT or KEXDH_REPLY message. */
      closure->kex_state = KEX_STATE_IN_PROGRESS;
      lsh_string_free(packet);
      return;

    case KEX_STATE_IN_PROGRESS:
      if ( (msg == SSH_MSG_NEWKEYS)
	   || (msg == SSH_MSG_KEXINIT))
	{
	  werror("Unexpected KEXINIT or NEWKEYS message!\n");
	  PROTOCOL_ERROR(closure->e, "Unexpected KEXINIT or NEWKEYS message!");
	  return;
	}
      break;
    case KEX_STATE_NEWKEYS:
      if ( (msg != SSH_MSG_NEWKEYS)
	   && (msg != SSH_MSG_DISCONNECT) )
	{
	  werror("Expected NEWKEYS message, but received message %i!\n",
		 msg);
	  PROTOCOL_ERROR(closure->e, "Expected NEWKEYS message");
	  return;
	}
      break;
    default:
      fatal("handle_connection: Internal error.\n");
    }

  HANDLE_PACKET(closure->dispatch[msg], closure, packet);
}

static void
do_fail(struct packet_handler *closure UNUSED,
	struct ssh_connection *connection,
	struct lsh_string *packet)
{
  lsh_string_free(packet);

  PROTOCOL_ERROR(connection->e, NULL);
}

static struct packet_handler fail_handler =
{ STATIC_HEADER, do_fail };

static void
do_unimplemented(struct packet_handler *closure UNUSED,
		 struct ssh_connection *connection,
		 struct lsh_string *packet)
{
  werror("Received packet of unimplemented type %i.\n",
	 packet->data[0]);

  C_WRITE(connection,
	  ssh_format("%c%i",
		     SSH_MSG_UNIMPLEMENTED,
		     packet->sequence_number));
  
  lsh_string_free(packet);
}

static struct packet_handler unimplemented_handler =
{ STATIC_HEADER, do_unimplemented };


/* GABA:
   (class
     (name exc_protocol_handler)
     (super exception_handler)
     (vars
       (connection object ssh_connection)))
*/

static void
do_exc_protocol_handler(struct exception_handler *s,
			const struct exception *e)
{
  CAST(exc_protocol_handler, self, s);

  switch (e->type)
    {
    case EXC_PROTOCOL:
      {
	CAST_SUBTYPE(protocol_exception, exc, e);
	if (exc->reason)
	  C_WRITE(self->connection, format_disconnect(exc->reason, exc->super.msg, ""));
	
	EXCEPTION_RAISE(self->super.parent, &finish_read_exception);
      }
      break;

    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }
}

struct exception_handler *
make_exc_protocol_handler(struct ssh_connection *connection,
			  struct exception_handler *parent,
			  const char *context)
{
  NEW(exc_protocol_handler, self);

  self->super.parent = parent;
  self->super.raise = do_exc_protocol_handler;
  self->super.context = context;
  
  self->connection = connection;

  return &self->super;
}

struct ssh_connection *
make_ssh_connection(UINT32 flags,
		    struct address_info *peer,
		    const char *debug_comment,
		    struct command_continuation *c,
		    struct exception_handler *e)
{
  int i;

  NEW(ssh_connection, connection);

  connection->flags = flags;
  connection->peer = peer;
  
  connection->debug_comment = debug_comment;
  connection->super.write = handle_connection;

  /* Exception handler that sends a proper disconnect message on protocol errors */
  connection->e = make_exc_protocol_handler(connection, e, HANDLER_CONTEXT);

  connection->established = c;
  
  /* Initialize instance variables */

  connection->versions[CONNECTION_SERVER]
    = connection->versions[CONNECTION_CLIENT]
    = connection->session_id = NULL;

  connection->peer_flags = 0;
  connection->user = NULL;
  
  connection->resources = empty_resource_list();
  
  connection->rec_max_packet = SSH_MAX_PACKET;
  connection->rec_mac = NULL;
  connection->rec_crypto = NULL;

  connection->send_mac = NULL;
  connection->send_crypto = NULL;

  connection->busy = 0;
  
  connection->kex_state = KEX_STATE_INIT;

  connection->kexinits[CONNECTION_CLIENT]
    = connection->kexinits[CONNECTION_SERVER] = NULL;

  connection->literal_kexinits[CONNECTION_CLIENT]
    = connection->literal_kexinits[CONNECTION_SERVER] = NULL;

  connection->newkeys = NULL;
  
  /* Initialize dispatch */
  connection->ignore = make_ignore_handler();
  connection->unimplemented = &unimplemented_handler;
  connection->fail = &fail_handler;
  
  for (i = 0; i < 0x100; i++)
    connection->dispatch[i] = connection->unimplemented;

  connection->dispatch[0] = connection->fail;
  connection->dispatch[SSH_MSG_DISCONNECT] = &disconnect_handler;
  connection->dispatch[SSH_MSG_IGNORE] = connection->ignore;
  connection->dispatch[SSH_MSG_UNIMPLEMENTED] = connection->ignore;

  connection->dispatch[SSH_MSG_DEBUG] = make_rec_debug_handler();

  
  /* Make all other known message types terminate the connection */

  connection->dispatch[SSH_MSG_SERVICE_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = connection->fail;
  connection->dispatch[SSH_MSG_NEWKEYS] = connection->fail;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_BANNER] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_PK_OK] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_PASSWD_CHANGEREQ] = connection->fail;
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_REQUEST_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_REQUEST_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_EXTENDED_DATA] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_FAILURE] = connection->fail;
  
  return connection;
}

void connection_init_io(struct ssh_connection *connection,
			struct abstract_write *raw,
			struct randomness *r)
{
  /* Initialize i/o hooks */
  connection->raw = raw;
  connection->write =
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

  /* Initial encryption state */
  connection->send_crypto = connection->rec_crypto = NULL;
  connection->send_mac = connection->rec_mac = NULL;
  connection->send_compress = connection->rec_compress = NULL;
}

/* Serialization. Breaks if we ever return to the main loop with the
 * connection locked.
 *
 * A better implementation should communicate with the packet source
 * to stop reading packets while the connection is locked. Perhaps by
 * raising appropriate exceptions, if we are to keep the connection
 * code free from i/o.*/

void connection_lock(struct ssh_connection *self)
{
  assert(!self->busy);
  self->busy = 1;
}

void connection_unlock(struct ssh_connection *self)
{
  assert(self->busy);
  self->busy = 0;
}

/* ;; GABA:
   (class
     (name handshake_command)
     (super command)
     (vars
       ; CONNECTION_SERVER or CONNECTION_CLIENT
       (mode . int)))
       */
