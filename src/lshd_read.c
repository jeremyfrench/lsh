/* lshd_read.c
 *
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
#include <string.h>

#include "nettle/macros.h"

#include "crypto.h"
#include "lsh_string.h"
#include "lshd.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd_read.c.x"

struct lshd_read_state *
make_lshd_read_state(struct header_callback *process,
		     struct error_callback *error)
{
  NEW(lshd_read_state, self);
  init_ssh_read_state(&self->super, SSH_MAX_BLOCK_SIZE, 8, process, error);
  self->sequence_number = 0;

  return self;
}


/* GABA:
   (class
     (name lshd_process_ssh_header)
     (super header_callback)
     (vars
       (sequence_number . uint32_t);
       (connection object lshd_connection)))
*/

static struct lsh_string *
lshd_process_ssh_header(struct header_callback *s, struct ssh_read_state *rs,
			uint32_t *done)
{
  CAST(lshd_process_ssh_header, self, s);
  CAST(lshd_read_state, state, rs);

  struct lshd_connection *connection = self->connection;
  
  const uint8_t *header;
  uint32_t length;
  uint32_t block_size;
  uint32_t mac_size;
  struct lsh_string *packet;
  
  block_size = connection->rec_crypto
    ? connection->rec_crypto->block_size : 8;

  if (connection->rec_crypto)
    {
      assert(state->super.header_length == block_size);
      CRYPT(connection->rec_crypto,
	    block_size,
	    state->super.header, 0,
	    state->super.header, 0);
    }
  header = lsh_string_data(state->super.header);
  length = READ_UINT32(header);

  /* NOTE: We don't implement a limit at _exactly_
   * rec_max_packet, as we don't include the length field
   * and MAC in the comparison below. */
  if (length > (connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("read_packet: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, connection->rec_max_packet);
		  
      connection_error(connection, "Packet too large");
      return NULL;
    }

  if ( (length < 12)
       || (length < (block_size - 4))
       || ( (length + 4) % block_size))
    {
      werror("read_packet: Bad packet length %i\n",
	     length);
      connection_error(connection, "Invalid packet length");
      return NULL;
    }
  
  if (connection->rec_mac)
    {
      uint8_t s[4];
      WRITE_UINT32(s, self->sequence_number);
      MAC_UPDATE(connection->rec_mac, 4, s);
      MAC_UPDATE(connection->rec_mac,
		 block_size, header);
    }

  state->padding = header[4];
  
  if ( (state->padding < 4)
       || (state->padding >= length) )
    {
      connection_error(connection, "Bogus padding length.");
      return NULL;
    }
  mac_size = connection->rec_mac ? connection->rec_mac->mac_size : 0;
  
  packet = lsh_string_alloc(length - 1 + mac_size);
  lsh_string_write(packet, 0, block_size - 5, header + 5);
  lsh_string_set_sequence_number(packet, self->sequence_number++);
  
  if (block_size - 5 == length + mac_size)
    {
      werror("Entire packet fit in first block.\n");

      /* This can happen only if we're using a cipher with a large
	 block size, and no mac. */
      assert(!connection->rec_mac);
      lsh_string_trunc(packet, length);
      lshd_handle_ssh_packet(connection, packet);

      return NULL;
    }

  *done = block_size - 5;
  return packet;
}

struct header_callback *
make_lshd_process_ssh_header(struct lshd_connection *connection)
{
  NEW(lshd_process_ssh_header, self);
  self->super.process = lshd_process_ssh_header;
  self->connection = connection;

  return &self->super;
}

void
lshd_handle_packet(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(lshd_read_handler, self, s);
  struct lshd_connection *connection = self->connection;

  uint32_t length;
  uint32_t block_size;
  uint32_t mac_size;
  uint32_t done;

  if (!packet)
    {
      /* EOF */
      connection_disconnect(connection, 0, NULL);
      return;
    }

  block_size = connection->rec_crypto
    ? connection->rec_crypto->block_size : 8;

  mac_size = connection->rec_mac ? connection->rec_mac->mac_size : 0;

  length = lsh_string_length(packet);
  assert(length >= connection->reader->padding + mac_size);

  /* The first block_size - 5 octets were part of the header, and
     are decrypted already. Decrypt the rest. */
  done = block_size - 5;
  
  if (length > done + mac_size)
    {
      /* We have more data to process */
      uint32_t left = length - done - mac_size;
      
      if (connection->rec_crypto)
	CRYPT(connection->rec_crypto,
	      length - mac_size - done,
	      packet, done, packet, done);

      if (connection->rec_mac)
	MAC_UPDATE(connection->rec_mac, left,
		   lsh_string_data(packet) + done);
    }
  if (connection->rec_mac)
    {
      struct lsh_string *mac = lsh_string_alloc(mac_size);
      MAC_DIGEST(connection->rec_mac, mac, 0);
      if (memcmp(lsh_string_data(mac),
		 lsh_string_data(packet) + length - mac_size,
		 mac_size))
	{
	  connection_disconnect(connection,
				SSH_DISCONNECT_MAC_ERROR,
				"Invalid MAC");
	  return;
	}
    }
  length -= mac_size + connection->reader->padding;
  lsh_string_trunc(packet, length);
  
  lshd_handle_ssh_packet(connection, packet);
}
