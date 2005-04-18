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

#include "transport.h"

#include "crypto.h"
#include "compress.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "transport_read.c.x"


/* How much data to read ahead */
#define TRANSPORT_READ_AHEAD 1000

/* GABA:
   (class
     (name transport_read_state)
     (vars
       (input_buffer string)
       (start . uint32_t)
       (length . uint32_t)

       (mac object mac_instance)
       (crypto object crypto_instance)
       (inflate object compress_instance)
       (seqno . uint32_t)

       (packet_length . uint32_t)
       (padding . uint8_t)

       ; The length of payload, padding and mac for current packet
       (total_length . uint32_t)

       (mac_buffer string)
       (output_buffer string)))
*/

struct transport_read_state *
make_transport_read_state(void)
{
  NEW(transport_read_state, self);
  self->input_buffer = lsh_string_alloc(SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ);
  self->start = self->length = 0;

  self->mac_buffer = lsh_string_alloc(SSH_MAX_MAC_SIZE);
  self->output_buffer = lsh_string_alloc(SSH_MAX_PACKET + 1);

  return self;
}

/* Returns -1 on error, 0 at EOF, and 1 for success. */
static int
read_some(struct transport_read_state *self, int fd, uint32_t limit)
{
  uint32_t left;
  int res;
  
  assert(limit < lsh_string_length(self->input_buffer));
  assert(self->length < limit);

  if (self->start + limit > lsh_string_length(self->input_buffer))
    {
      assert(self->start > 0);
      lsh_string_move(self->input_buffer, 0, self->length, self->start);
      self->start = 0;
    }
  
  left = limit - self->length;
  res = lsh_string_read(self->input_buffer, self->start + self->length, fd, left);
  if (res < 0)
    return 0;
  else if (res == 0)
    return 0;

  self->length += res;
  return 1;
}

/* Find line terminator */
static int
find_line(struct transport_read_state *self,
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
      self->start += line_length + 1;
      self->length -= line_length + 1;
      return 1;
    }
  else if (self->length >= SSH_MAX_LINE)
    {
    line_too_long:
      *error = 0;
      *msg = "Line too long";
      return -2;
    }
  else return 0;
}

int
transport_read_line(struct transport_read_state *self, int fd,
		    int *error, const char **msg,
		    uint32_t *length, const uint8_t **line)
{
  int res;
  
  if (self->length == 0)
    self->start = 0;

  else
    {
      res = find_line(self, error, msg, length, line);
      if (res != 0)
	return res;
    }

  if (fd < 0)
    return 0;

  res = read_some(self, fd, TRANSPORT_READ_AHEAD);
  if (res == 0)
    { /* EOF */
      if (self->length == 0)
	{
	  *length = 0;
	  *line = NULL;
	  return 1;
	}
      else
	{
	  *error = 0;
	  return -1;
	}
    }
  else if (res < 0)
    {
      if (errno == EWOULDBLOCK || errno == EINTR)
	return 0;

      *error = errno;
      return -1;
    }
  return find_line(self, error, msg, length, line);
}  

static int
decode_packet(struct transport_read_state *self,
	      int *error, const char **msg,
	      uint32_t *seqno,
	      uint32_t *length_p, const uint8_t **data_p)
{
  uint32_t block_size = self->crypto ? self->crypto->block_size : 8;
  uint32_t mac_size = self->mac ? self->mac->mac_size : 0;

  uint32_t crypt_done = block_size - 5;
  uint32_t crypt_left = self->total_length - (crypt_done + mac_size);

  const uint8_t *data = lsh_string_data(self->input_buffer) + self->start;
  uint32_t length;
  
  if (self->crypto && crypt_left > 0)
    CRYPT(self->crypto, crypt_left,
	  self->input_buffer, self->start + crypt_done,
	  self->input_buffer, self->start + crypt_done);
  
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
	  return -2;
	}
    }

  length = self->total_length - mac_size - self->padding;
  self->start += self->total_length;
  self->length -= self->total_length;
  
  if (self->inflate)
    fatal("Inflating not yet implemented.\n");

  *seqno = self->seqno;
  *data_p = data;
  *length_p = length;

  return 1;
}
		   
/* First reads the entire packet into the input_buffer, decrypting it
   in place. Next, reads the mac and verifies it. */
int
transport_read_packet(struct transport_read_state *self, int fd,
		      int *error, const char **msg,
		      uint32_t *seqno,
		      uint32_t *length, const uint8_t **data)
{
  uint32_t block_size = self->crypto ? self->crypto->block_size : 8;

  if (self->length < block_size)
    {
      const uint8_t *header;
      uint32_t packet_length;
      int res;
      
      if (fd < 0)
	return 0;

      res = read_some(self, fd, TRANSPORT_READ_AHEAD);

      if (res == 0)
	{
	  if (self->length == 0)
	    {
	      *length = 0;
	      *data = NULL;
	      return 1;
	    }
	  else
	    {
	      *error = 0;
	      return -1;
	    }
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK || errno == EINTR)
	    return 0;

	  *error = errno;
	  return -1;
	}
      if (self->length < block_size)
	return 0;

      if (self->crypto)
	{
	  CRYPT(self->crypto, block_size,
		self->input_buffer, self->start,
		self->input_buffer, self->start);
	}

      header = lsh_string_data(self->input_buffer) + self->start;;
      
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
	  return -2;
	}

      if ( (packet_length < 12)
	   || (packet_length < (block_size - 4))
	   || ( (packet_length + 4) % block_size))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Invalid packet length";
	  return -2;
	}
      
      /* Approximate test, to avoid overflow when computing the total
	 size. Precice comparison to available buffer space comes
	 later. */
      if (self->packet_length > (SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Packet too large";
	  return -2;
	}

      self->total_length = self->packet_length - 1;
      if (self->mac)
	self->total_length += self->mac->mac_size;

      if (self->total_length > lsh_string_length(self->input_buffer))
	{
	  *error = SSH_DISCONNECT_PROTOCOL_ERROR;
	  *msg = "Packet too large";
	  return -2;
	}
      self->start += 5;
      self->length -= 5;
      if (self->length < self->total_length)
	return 0;

      return decode_packet(self, error, msg,
			   seqno, length, data);
    }
  if (self->length < self->total_length)
    {
      int res;
      
      if (fd < 0)
	return 0;

      res = read_some(self, fd, self->total_length + TRANSPORT_READ_AHEAD);

      if (res == 0)
	{
	  *error = 0;
	  return -1;
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK || errno == EINTR)
	    return 0;

	  *error = errno;
	  return -1;
	}

      if (self->length < self->total_length)
	return 0;
    }
  return decode_packet(self, error, msg,
		       seqno, length, data);
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
