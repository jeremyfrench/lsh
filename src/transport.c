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

#define GABA_DEFINE
# include "transport.h.x"
#undef GABA_DEFINE

static struct transport_read_state *
make_transport_connection_read_state(struct transport_connection *connection);

void
init_transport_connection(struct transport_connection *self,
			  void (*kill)(struct resource *s),
			  struct randomness *random, struct algorithms *algorithms,
			  int ssh_input, int ssh_output,
			  void (*handler)(struct transport_connection *connection,
					  struct lsh_string *packet))
{
  init_resource(&self->super, kill);
  
  self->random = random;
  self->algorithms = algorithms;

  init_kexinit_state(&self->kexinit_state);
  self->session_id = NULL;
  self->keyexchange_handler = NULL;

  self->ssh_input = ssh_input;
  self->reader = make_transport_connection_read_state();

  self->ssh_output = ssh_output;
  self->send_mac = NULL;
  self->send_crypto = NULL;
  self->send_compress = NULL;
  self->seqno = 0;

  self->handler = handler;  
}

void
kill_transport_close(struct transport_connection *self)
{
  /* FIXME: Let the write buffer empty before closing the out fd. */

  self->super.alive = 0;

  global_oop_source->cancel_fd(global_oop_source,
			       self->ssh_input, OOP_READ);
  close(self->ssh_input);

  global_oop_source->cancel_fd(global_oop_source,
			       self->ssh_output, OOP_WRITE);

  if (self->ssh_output != self->ssh_input)
    close(self->ssh_output);
}

void
transport_write_data(struct transport_connection *connection, struct lsh_string *data)
{
  if (!connection->super.alive)
    {
      werror("connection_write_data: Connection is dead.\n");
      lsh_string_free(data);
      return;
    }
  /* FIXME: If ssh_write_data returns 0, we need to but the connection
     to sleep and wake it up later. */
  if (ssh_write_data(connection->writer,
		     global_oop_source, connection->ssh_output, data) < 0)
    {
      werror("write failed: %e\n", errno);
      connection_disconnect(connection, 0, NULL);
    }  
}

void
transport_write_packet(struct transport_connection *connection, struct lsh_string *packet)
{
  transport_write_data(connection,
		       encrypt_packet(packet,
				      connection->send_compress,
				      connection->send_crypto,
				      connection->send_mac,
				      connection->config->random,
				      connection->send_seqno++));
}

void
transport_disconnect(struct transport_connection *connection,
		     int reason, const uint8_t *msg)
{
  if (reason)
    transport_write_packet(connection, format_disconnect(reason, msg, ""));

  KILL_RESOURCE(&connection->super);
};

/* GABA:
   (class
     (name transport_connection_read_state)
     (super transport_read_state)
     (vars
       (connection transport_connection)))
*/

/* Error callbacks for reading */
static void
transport_read_error(struct ssh_read_state *s, int error)
{
  CAST(transport_connection_read_state, self, s);
  werror("Read failed: %e\n", error);
  KILL(&self->connection->super);
}

static void
transport_protocol_error(struct transport_read_state *s, int reason, const char *msg)
{
  CAST(transport_connection_read_state, self, s);
  transport_disconnect(self->connection, reason, msg);
}

static struct transport_read_state *
make_transport_connection_read_state(struct transport_connection *connection)
{
  NEW(transport_connection_read_state, self);
  init_transport_read_state(&self->super, SSH_MAX_PACKET,
			    transport_read_error, transport_protocol_error);

  self->connection = connection;

  return self;
}

static void
transport_send_kexinit(struct transport_connection *connection, unsigned is_server)
{
  struct lsh_string *s;
  struct kexinit *kex
    = connection->kex.kexinit[is_server]
    = MAKE_KEXINIT(connection->config->kexinit);
  
  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.state == KEX_STATE_INIT);

  /* FIXME: Deal with timeout */
  
  s = format_kexinit(kex);
  connection->kex.literal_kexinit[is_server] = lsh_string_dup(s); 
  transport_write_packet(connection, s);

  if (kex->first_kex_packet)
    fatal("Not implemented\n");
}

/* Handles decrypted packets. The various handler functions called
   from here should *not* free the packet. FIXME: Better to change
   this? */
void
transport_handle_ssh_packet(struct transport_read_state *s, struct lsh_string *packet)
{
  CAST(transport_connection_read_state, self, s);
  struct transport_connection *connection = self->connection;
  
  uint32_t length = lsh_string_length(packet);
  uint8_t msg;

  werror("Received packet: %xS\n", packet);
  if (!length)
    {
      werror("Received empty packet!\n");
      lsh_string_free(packet);
      transport_error(connection, "Empty packet");
      return;
    }

  if (length > connection->reader->super.max_packet)
    {
      werror("Packet too large!\n");
      transport_error(connection, "Packet too large");
      lsh_string_free(packet);
      return;
    }

  msg = lsh_string_data(packet)[0];

  /* Messages of type IGNORE, DISCONNECT and DEBUG are always
     acceptable. */
  if (msg == SSH_MSG_IGNORE)
    {
      /* Ignore it */
    }

  else if (msg == SSH_MSG_DISCONNECT)
    transport_disconnect(connection, 0, NULL);

  else if (msg == SSH_MSG_DEBUG)
    {
      /* FIXME: In verbose mode, display message */
    }

  /* Otherwise, behaviour depends on te kex state */
  else switch (connection->kex.state)
    {
    case KEX_STATE_IGNORE:
      connection->kex.state = KEX_STATE_IN_PROGRESS;
      break;

    case KEX_STATE_IN_PROGRESS:
      if (msg < SSH_FIRST_KEYEXCHANGE_SPECIFIC
	  || msg >= SSH_FIRST_USERAUTH_GENERIC)
	transport_error(connection, "Unexpected message during key exchange");
      else
	connection->kex_handler(connection->kex_handler, connection, packet);

      break;

    case KEX_STATE_NEWKEYS:
      if (msg != SSH_MSG_NEWKEYS)
	connection_error(connection, "NEWKEYS expected");
      else
	{
	  if (length == 1)
	    {
	      transport_read_newkeys(connection->reader, connection->new_mac,
				     connection->new_crypto, connection->new_compression);
	      connection->new_mac = NULL;
	      connection->new_crypto = NULL;
	      connection->new_compression = NULL;

	      reset_kexinit_state(&connection->kex);
	      
	    }
	  
	}
      break;

    case KEX_STATE_INIT:
      if (msg == SSH_MSG_KEXINIT)
	lshd_kexinit_handler(connection, packet);

      else if (msg == SSH_MSG_SERVICE_REQUEST)
	{
	  if (connection->service_state != SERVICE_ENABLED)
	    connection_disconnect(connection,
				  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				  "Unexpected service request");
	  else
	    lshd_service_request_handler(connection, packet);
	}
      else if (msg >= SSH_FIRST_USERAUTH_GENERIC
	       && connection->service_state == SERVICE_STARTED)
	lshd_service_handler(connection, packet);

      else
	connection_write_packet(
	  connection,
	  format_unimplemented(lsh_string_sequence_number(packet)));

      break;
    }

  lsh_string_free(packet);
}

