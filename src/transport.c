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
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "transport.h"

#define GABA_DEFINE
# include "transport.h.x"
#undef GABA_DEFINE

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
  self->new_compress = NULL;
  
  self->ssh_input = ssh_input;
  self->reader = make_transport_read_state();

  self->ssh_output = ssh_output;
  self->writer = make_transport_write_state();

  self->event_handler = event;
}

static void *
oop_read_ssh(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(transport_connection, connection, (struct lsh_object *) state);
  int error;
  const char *error_msg;
  int res = 0;

  assert(source == connection->ctx->oop);
  assert(event == OOP_READ);
  assert(fd == connection->ssh_input);

  while (connection->line_handler && connection->ssh_input >= 0)
    {
      uint32_t length;
      const uint8_t *line;
  
      res = transport_read_line(connection->reader, fd, &error, &error_msg,
				&length, &line);
      if (res != 1)
	goto done;
      
      fd = -1;

      if (!line)
	{
	  werror("Unexpected EOF at start of line.\n");
	  transport_close(connection, 0);
	}
      else
	connection->line_handler(connection, length, line);
    }
  while (connection->ssh_input >= 0)
    {
      uint32_t seqno;
      uint32_t length;
      const uint8_t *packet;
      
      uint8_t msg;

      res = transport_read_packet(connection->reader, fd, &error, &error_msg,
				  &seqno, &length, &packet);
      if (res != 1)
	goto done;
      
      fd = -1;
      
      /* Process packet */
      if (!packet)
	{
	  werror("Unexpected EOF at start of packet.\n");
	  transport_close(connection, 0);	  
	}
      if (length == 0)
	{
	  transport_protocol_error(connection, "Received empty packet");
	  return OOP_CONTINUE;
	}
      msg = packet[0];

      /* Messages of type IGNORE, DISCONNECT and DEBUG are always
	 acceptable. */
      if (msg == SSH_MSG_IGNORE)
	{
	  /* Do nothing */	  
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
      else switch (connection->kex.state)
	{
	default:
	  abort();
	case KEX_STATE_IGNORE:
	  connection->kex.state = KEX_STATE_IN_PROGRESS;
	  break;
	case KEX_STATE_IN_PROGRESS:
	  if (msg < SSH_FIRST_KEYEXCHANGE_SPECIFIC
	      || msg >= SSH_FIRST_USERAUTH_GENERIC)
	    transport_protocol_error(connection,
			    "Unexpected message during key exchange");
	  else
	    connection->keyexchange_handler->handler(connection->keyexchange_handler,
						     connection, length, packet);
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
				      connection->new_compress);
	      connection->new_mac = NULL;
	      connection->new_crypto = NULL;
	      connection->new_compress = NULL;
	    }
	  break;

	case KEX_STATE_INIT:
	  if (msg == SSH_MSG_KEXINIT)
	    transport_kexinit_handler(connection, length, packet);
	  else if (msg >= SSH_FIRST_USERAUTH_GENERIC)
	    connection->packet_handler(connection, length, packet);
	  else
	    transport_send_packet(connection, format_unimplemented(seqno));
	  break;
	}
      if (connection->ssh_input < 0)
	{
	  /* We've been closed? */
	  return OOP_CONTINUE;
	}      
    }
 done:
  switch (res)
    {
    default:
      abort();
    case 0:
      break;
    case -1:
      /* I/O error */
      werror("Read error: %e\n", error);
      transport_close(connection, 0);
      break;
    case -2:
      transport_disconnect(connection, error, error_msg);
      break;
    }
  return OOP_CONTINUE;
}

static void *
oop_write_ssh(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(transport_connection, connection, (struct lsh_object *) state);
  int res;

  assert(source == connection->ctx->oop);
  assert(event == OOP_WRITE);
  assert(fd == connection->ssh_output);

  res = transport_write_flush(connection->writer, fd);
  switch(res)
    {
    default: abort();
    case 0:
      /* More to write */
      break;
    case 1:
      transport_write_pending(connection, 0);
      break;
    case -1:
      if (errno != EWOULDBLOCK)
	{
	  werror("Write failed: %e\n", errno);
	  transport_close(connection, 0);
	}
      break;
    }
  return OOP_CONTINUE;
}

void
transport_write_pending(struct transport_connection *connection, int pending)
{
  if (pending != connection->write_pending)
    {
      oop_source *source = connection->ctx->oop;

      connection->write_pending = pending;
      if (pending)
	{
	  source->on_fd(source, connection->ssh_output, OOP_WRITE, oop_write_ssh, connection);
	  connection->event_handler(connection, TRANSPORT_EVENT_STOP_APPLICATION);
	}
      else
	{
	  source->cancel_fd(source, connection->ssh_output, OOP_WRITE);
	  connection->event_handler(connection, TRANSPORT_EVENT_START_APPLICATION);	  
	}      
    }
}

/* FIXME: Naming is unfortunate, with transport_write_packet vs
   transport_send_packet */
void
transport_send_packet(struct transport_connection *connection,
		      struct lsh_string *packet)
{
  int res;
  
  if (!connection->super.alive)
    {
      werror("connection_write_data: Connection is dead.\n");
      lsh_string_free(packet);
      return;
    }
  
  res = transport_write_packet(connection->writer, connection->ssh_output,
			       1, packet, connection->ctx->random);
  switch(res)
  {
  case -2:
    werror("Remote peer not responsive. Disconnecting.\n");
    transport_close(connection, 0);
    break;
  case -1:
    werror("Write failed: %e\n", errno);
    transport_close(connection, 0);
    break;
  case 0:
    transport_write_pending(connection, 1);
    break;
  case 1:
    transport_write_pending(connection, 0);
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
    transport_send_packet(connection, format_disconnect(reason, msg, ""));

  transport_close(connection, 1);
};

static void
transport_send_kexinit(struct transport_connection *connection,
		       unsigned is_server)
{
  struct lsh_string *s;
  struct kexinit *kex
    = connection->kex.kexinit[is_server]
    = MAKE_KEXINIT(connection->ctx->kexinit);
  
  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.state == KEX_STATE_INIT);

  /* FIXME: Deal with timeout */
  
  s = format_kexinit(kex);
  connection->kex.literal_kexinit[is_server] = lsh_string_dup(s); 
  transport_send_packet(connection, s);

  if (kex->first_kex_packet)
    fatal("Not implemented\n");
}
