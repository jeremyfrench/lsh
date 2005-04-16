/* transport_read.c
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
#include "compress.h"
#include "lsh_string.h"
#include "transport_read.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "transport_read.h.x"
#undef GABA_DEFINE

static void
maybe_inflate_packet(struct transport_read_state *self, struct lsh_string *packet)
{
  if (self->compression)
    {
      packet = CODEC(self->compression, packet, 1);
      if (!packet)
	{
	  self->protocol_error(self, SSH_DISCONNECT_COMPRESSION_ERROR,
			       "Inflating compressed data failed.");
	  return;
	}
    }
  self->handle_packet(self, packet);  
}

static struct lsh_string *
process_ssh_header(struct ssh_read_state *s)
{
  CAST_SUBTYPE(transport_read_state, self, s);

  const uint8_t *header;
  uint32_t length;
  uint32_t block_size;
  uint32_t mac_size;
  struct lsh_string *packet;
  
  block_size = self->crypto
    ? self->crypto->block_size : 8;

  if (self->crypto)
    {
      assert(self->super.header_length == block_size);
      CRYPT(self->crypto,
	    block_size,
	    self->super.header, 0,
	    self->super.header, 0);
    }
  header = lsh_string_data(self->super.header);
  length = READ_UINT32(header);

  /* NOTE: We don't implement a limit at _exactly_
   * rec_max_packet, as we don't include the length field
   * and MAC in the comparison below. */
  if (length > (self->max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("process_ssh_header: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, self->max_packet);

      self->protocol_error(self, SSH_DISCONNECT_PROTOCOL_ERROR, "Packet too large");
      return NULL;
    }

  if ( (length < 12)
       || (length < (block_size - 4))
       || ( (length + 4) % block_size))
    {
      werror("process_ssh_header: Bad packet length %i\n",
	     length);
      self->protocol_error(self, SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid packet length");
      return NULL;
    }
  
  if (self->mac)
    {
      uint8_t s[4];
      WRITE_UINT32(s, self->sequence_number);
      MAC_UPDATE(self->mac, 4, s);
      MAC_UPDATE(self->mac,
		 block_size, header);
    }

  self->padding = header[4];
  
  if ( (self->padding < 4)
       || (self->padding >= length) )
    {      
      self->protocol_error(self, SSH_DISCONNECT_PROTOCOL_ERROR, "Bogus padding length.");
      return NULL;
    }
  mac_size = self->mac ? self->mac->mac_size : 0;
  
  packet = lsh_string_alloc(length - 1 + mac_size);
  lsh_string_write(packet, 0, block_size - 5, header + 5);
  lsh_string_set_sequence_number(packet, self->sequence_number++);
  
  if (block_size - 5 == length + mac_size)
    {
      werror("Entire packet fit in first block.\n");

      /* This can happen only if we're using a cipher with a large
	 block size, and no mac. */
      assert(!self->mac);
      lsh_string_trunc(packet, length);
      maybe_inflate_packet(self, packet);

      return NULL;
    }

  self->super.pos = block_size - 5;
  return packet;
}

static void
transport_handle_packet(struct ssh_read_state *s, struct lsh_string *packet)
{
  CAST_SUBTYPE(transport_read_state, self, s);

  uint32_t length;
  uint32_t block_size;
  uint32_t mac_size;
  uint32_t done;

  if (!packet)
    {
      /* EOF */
      self->protocol_error(self, SSH_DISCONNECT_PROTOCOL_ERROR, "Unexpected EOF");
      return;
    }

  block_size = self->crypto
    ? self->crypto->block_size : 8;

  mac_size = self->mac ? self->mac->mac_size : 0;

  length = lsh_string_length(packet);
  assert(length >= self->padding + mac_size);

  /* The first block_size - 5 octets were part of the header, and
     are decrypted already. Decrypt the rest. */
  done = block_size - 5;
  
  if (length > done + mac_size)
    {
      /* We have more data to process */
      uint32_t left = length - done - mac_size;
      
      if (self->crypto)
	CRYPT(self->crypto,
	      length - mac_size - done,
	      packet, done, packet, done);

      if (self->mac)
	MAC_UPDATE(self->mac, left,
		   lsh_string_data(packet) + done);
    }
  if (self->mac)
    {
      struct lsh_string *mac = lsh_string_alloc(mac_size);
      MAC_DIGEST(self->mac, mac, 0);
      if (memcmp(lsh_string_data(mac),
		 lsh_string_data(packet) + length - mac_size,
		 mac_size))
	{
	  self->protocol_error(self, SSH_DISCONNECT_MAC_ERROR, "Invalid MAC");
	  return;
	}
    }
  length -= mac_size + self->padding;
  lsh_string_trunc(packet, length);

  maybe_inflate_packet(self, packet);
}

void
init_transport_read_state(struct transport_read_state *self,
			  uint32_t max_packet,
			  void (*io_error)(struct ssh_read_state *state, int error),
			  void (*protocol_error)
			  (struct transport_read_state *state, int reason, const char *msg))
{
  init_ssh_read_state(&self->super, SSH_MAX_BLOCK_SIZE, 8,
		      process_ssh_header, io_error);

  self->max_packet = max_packet;
  self->mac = NULL;
  self->crypto = NULL;
  self->compression = NULL;
  self->sequence_number = 0;

  self->protocol_error = protocol_error;

}

struct transport_read_state *
make_transport_read_state(uint32_t max_packet,
			  void (*io_error)(struct ssh_read_state *state, int error),
			  void (*protocol_error)
			    (struct transport_read_state *state, int reason, const char *msg))
{
  NEW(transport_read_state, self);
  init_transport_read_state(self, max_packet, io_error, protocol_error);

  return self;
}

void
transport_read_packet(struct transport_read_state *self,
		      oop_source *source, int fd,
		      void (*handle_packet)
		        (struct transport_read_state *state, struct lsh_string *packet))
{
  self->handle_packet = handle_packet;
  
  ssh_read_packet(&self->super, source, fd, transport_handle_packet);
}
