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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

/* For ioctl and FIONREAD */
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "nettle/macros.h"

#include "transport.h"

#include "crypto.h"
#include "compress.h"
#include "io.h"
#include "lsh_string.h"
#include "randomness.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "transport_read.c.x"

#ifndef DEBUG_PACKET_HEADER
#define DEBUG_PACKET_HEADER 0
#endif

/* How much data to read ahead */
#define TRANSPORT_READ_AHEAD 1000

/* GABA:
   (class
     (name transport_read_state)
     (super ssh_read_state)
     (vars
       (mac object mac_instance)
       (crypto object crypto_instance)
       (inflate object compress_instance)
       (seqno . uint32_t)

       (padding . uint8_t)

       ; The length of payload, padding and mac for current packet
       ; Zero means that we need to process the packet header.
       (total_length . uint32_t)

       (mac_buffer string)))
*/

struct transport_read_state *
make_transport_read_state(void)
{
  NEW(transport_read_state, self);
  init_ssh_read_state(&self->super, SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ);

  self->mac = NULL;
  self->crypto = NULL;
  self->inflate = NULL;
  self->seqno = 0;

  self->padding = 0;
  self->total_length = 0;
  
  self->mac_buffer = lsh_string_alloc(SSH_MAX_MAC_SIZE);
  
  return self;
}

/* Find line terminator */
static enum ssh_read_status
find_line(struct ssh_read_state *self,
	  int *error, const char **msg,
	  uint32_t *length, const uint8_t **line)
{
  const uint8_t *data = lsh_string_data(self->input_buffer) + self->start;
  const uint8_t *eol = memchr(data, 0xa, self->length);
  if (eol)
    {
      /* Does not include the newline character */
      uint32_t line_length = eol - data;
      if (line_length >= SSH_MAX_LINE)
	goto line_too_long;
      
      *line = data;
      /* Chop off any carriage return character */
      *length = line_length - (line_length > 0 && data[line_length - 1] == 0xd);

      /* Skip newline character as well */
      line_length++;
      self->start += line_length;
      self->length -= line_length;
      return SSH_READ_COMPLETE;
    }
  else if (self->length >= SSH_MAX_LINE)
    {
    line_too_long:
      *error = 0;
      *msg = "Line too long";
      return SSH_READ_PROTOCOL_ERROR;
    }
  else
    return self->read_status;
}

enum ssh_read_status
transport_read_line(struct transport_read_state *self, int fd,
		    int *error, const char **msg,
		    uint32_t *length, const uint8_t **line)
{
  int res;
  
  if (self->super.length == 0)
    self->super.start = 0;

  else
    {
      enum ssh_read_status status;

      status = find_line(&self->super, error, msg, length, line);
      if (status <= SSH_READ_COMPLETE)
	return status;
    }

  if (fd < 0)
    return self->super.read_status;

  res = ssh_read_some(&self->super, fd, TRANSPORT_READ_AHEAD);
  if (res == 0)
    { /* EOF */
      if (self->super.length == 0)
	{
	  return SSH_READ_EOF;
	}
      else
	{
	  *error = 0;
	  return SSH_READ_PROTOCOL_ERROR;
	}
    }
  else if (res < 0)
    {
      if (errno == EWOULDBLOCK)
	return SSH_READ_PUSH;

      *error = errno;
      return SSH_READ_IO_ERROR;
    }
  return find_line(&self->super, error, msg, length, line);
}  

static enum ssh_read_status
decode_packet(struct transport_read_state *self,
	      int *error, const char **msg,
	      uint32_t *seqno,
	      uint32_t *length, struct lsh_string *output)
{
  uint32_t block_size = self->crypto ? self->crypto->block_size : 8;
  uint32_t mac_size = self->mac ? self->mac->mac_size : 0;

  uint32_t crypt_done = block_size - 5;
  uint32_t crypt_left = self->total_length - (crypt_done + mac_size);
  const uint8_t *data = lsh_string_data(self->super.input_buffer) + self->super.start;

  /* When inflating packets, we have to decrypt in place, and inflate
     into the output buffer. If we're not inflating, it is best to
     decrypt directly into the output buffer, avoiding an extra
     copying at the end.

     FIXME: But for simplicity, that's not yet implemented, we do
     everything in place and copy at the end. */

  if (self->crypto && crypt_left > 0)
    CRYPT(self->crypto, crypt_left,
	  self->super.input_buffer, self->super.start + crypt_done,
	  self->super.input_buffer, self->super.start + crypt_done);
  
  if (self->mac)
    {      
      if (crypt_left > 0)
	MAC_UPDATE(self->mac, crypt_left,
		   data + crypt_done);

      MAC_DIGEST(self->mac, self->mac_buffer, 0);
      if (0 != memcmp(lsh_string_data(self->mac_buffer),
		      data + self->total_length - mac_size,
		      mac_size))
	{
	  *error = SSH_DISCONNECT_MAC_ERROR;
	  *msg = "Invalid MAC";
	  return SSH_READ_PROTOCOL_ERROR;
	}
    }

  *length = self->total_length - mac_size - self->padding;
  self->super.start += self->total_length;
  self->super.length -= self->total_length;

  if (self->crypto)
    random_add(RANDOM_SOURCE_REMOTE,
	       self->padding,
	       data + self->total_length - mac_size - self->padding);

  /* Reset for next header */
  self->total_length = 0;

  *seqno = self->seqno++;
  
  if (self->inflate)
    *length = CODEC(self->inflate, output, 0, *length, data);
  else
    lsh_string_write(output, 0, *length, data);

  return SSH_READ_COMPLETE;
}

/* First reads the entire packet into the input_buffer, decrypting it
   in place. Next, reads the mac and verifies it. */
enum ssh_read_status
transport_read_packet(struct transport_read_state *self, int fd,
		      int *error, const char **msg,
		      uint32_t *seqno,
		      uint32_t *length, struct lsh_string *packet)
{
  uint32_t block_size = self->crypto ? self->crypto->block_size : 8;

  if (self->super.length < block_size)
    {
      int res;
      
      if (fd < 0)
	return self->super.read_status;

      res = ssh_read_some(&self->super, fd, TRANSPORT_READ_AHEAD);
      fd = -1;

      if (res == 0)
	{
	  if (self->super.length == 0)
	    return SSH_READ_EOF;
	  else
	    {
	      *error = 0;
	      *msg = "Unexpected EOF";
	      return SSH_READ_PROTOCOL_ERROR;
	    }
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK)
	    return SSH_READ_PUSH;

	  *error = errno;
	  return SSH_READ_IO_ERROR;
	}
      if (self->super.length < block_size)
	return self->super.read_status;
    }
  assert(self->super.length >= block_size);

  if (self->total_length == 0)
    {
      uint32_t packet_length;
      const uint8_t *header;
#if DEBUG_PACKET_HEADER
      uint8_t *raw = alloca (block_size);
      memcpy (raw, lsh_string_data(self->super.input_buffer) + self->super.start, block_size);
#endif
      /* Process header */
      if (self->crypto)
	{
	  CRYPT(self->crypto, block_size,
		self->super.input_buffer, self->super.start,
		self->super.input_buffer, self->super.start);
	}

      header = lsh_string_data(self->super.input_buffer) + self->super.start;
      
      if (self->mac)
	{
	  uint8_t s[4];
	  WRITE_UINT32(s, self->seqno);
	  MAC_UPDATE(self->mac, 4, s);
	  MAC_UPDATE(self->mac, block_size, header);
	}
      
      packet_length = READ_UINT32(header);
      self->padding = header[4];

      if ( (self->padding < 4)
	   || (self->padding >= packet_length) )
	{      
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Bogus padding length";
#if DEBUG_PACKET_HEADER
	  werror("raw header: %xs\n"
		 "decrypted header: %xs\n",
		 block_size, raw,
		 block_size, header);
#endif
	  return SSH_READ_PROTOCOL_ERROR;
	}

      if ( (packet_length < 12)
	   || (packet_length < (block_size - 4))
	   || ( (packet_length + 4) % block_size))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Invalid packet length";
#if DEBUG_PACKET_HEADER
	  werror("raw header: %xs\n"
		 "decrypted header: %xs\n",
		 block_size, raw,
		 block_size, header);
#endif
	  return SSH_READ_PROTOCOL_ERROR;
	}
      
      /* Approximate test, to avoid overflow when computing the total
	 size. Precise comparison to available buffer space comes
	 later. */
      if (packet_length > (SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Packet too large";
#if DEBUG_PACKET_HEADER
	  werror("raw header: %xs\n"
		 "decrypted header: %xs\n",
		 block_size, raw,
		 block_size, header);
#endif
	  return SSH_READ_PROTOCOL_ERROR;
	}

      self->total_length = packet_length - 1;
      if (self->mac)
	self->total_length += self->mac->mac_size;

      if (self->total_length > lsh_string_length(self->super.input_buffer))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Packet too large";
#if DEBUG_PACKET_HEADER
	  werror("raw header: %xs\n"
		 "decrypted header: %xs\n",
		 block_size, raw,
		 block_size, header);
#endif
	  return SSH_READ_PROTOCOL_ERROR;
	}
      self->super.start += 5;
      self->super.length -= 5;
    }
  if (self->super.length < self->total_length)
    {
      int res;
      
      if (fd < 0)
	return self->super.read_status;

      res = ssh_read_some(&self->super, fd, self->total_length + TRANSPORT_READ_AHEAD);

      if (res == 0)
	{
	  *error = 0;
	  *msg = "Unexpected EOF";
	  return SSH_READ_PROTOCOL_ERROR;
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK)
	    return SSH_READ_PUSH;

	  *error = errno;
	  return SSH_READ_IO_ERROR;
	}

      if (self->super.length < self->total_length)
	return self->super.read_status;
    }
  return decode_packet(self, error, msg,
		       seqno, length, packet);
}

void
transport_read_new_keys(struct transport_read_state *self,
			struct mac_instance *mac,
			struct crypto_instance *crypto,
			struct compress_instance *inflate)
{
  self->mac = mac;
  self->crypto = crypto;
  self->inflate = inflate;
}
