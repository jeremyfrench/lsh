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

  assert(self->super.header_length == block_size);
  
  if (self->crypto)
    {
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

void
transport_new_keys(struct transport_read_state *self,
		   struct mac_instance *mac, struct crypto_instance *crypto,
		   struct compress_instance *compression)
{
  self->mac = mac;
  self->crypto = crypto;
  self->compression = compression;
  
  self->super.header_length
    = keys->crypto ? keys->crypto->block_size : 8;
}

#if 0

#include "transport_read.h"

/* GABA:
   (class
     (name transport_read)
     (vars
       (input_buffer string)
       (start . uint32_t)
       (length . uint32_t)

       (mac object mac_instance)
       (crypto object crypto_instance)
       (inflate object compress_instance)

       (packet_length . uint32_t)
       (padding . uint8_t)

       ; The length of payload, padding and mac
       (total_length . uint32_t)

       (mac_buffer string)
       (output_buffer string)))
*/

struct transport_read *
make_transport_read(void)
{
  NEW(transport_read, self);
  self->input_buffer = lsh_string_alloc(SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ);
  self->start = self->end = 0;

  self->mac_buffer = lsh_string_alloc(SSH_MAX_MAC_SIZE);
  self->output_buffer = lsh_string_alloc(SSH_MAX_PACKET + 1);

  return self;
}

/* Returns -1 on error, 0 at EOF, and 1 for success. */
static int
read_some(struct transport_read *self, int fd, uint32_t limit)
{
  uint32_t left;
  int res;
  
  assert(limit < lsh_string_length(self->input_buffer));
  assert(self->length < limit);

  if (self->start + limit > lsh_string_length(self->input_buffer))
    {
      assert(start > 0);
      lsh_string_move(self->input_buffer, 0, self->length, self->start);
      self->start = 0;
    }
  
  left = limit - self->length;
  res = lsh_string_read(s, self->start + self->length, fd, left);
  if (res < 0)
    return 0;
  else if (res == 0)
    return 0;

  self->length += res;
  return 1;
}

/* Find line terminator */
static int
find_line(struct transport_read *self,
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

/* How much data to read at a time */
#define TRANSPORT_LINE_BUFFER 1000

int
transport_read_line(struct transport_read *self, int fd,
		    int *error, const char **msg,
		    uint32_t *length, const uint8_t **line)
{
  int res;
  
  if (self->length == 0)
    self->start = 0;

  else
    {
      res = find_line(self, length, line);
      if (res != 0)
	return res;
    }

  if (fd < 0)
    return 0;

  res = read_some(struct transport_read *self, fd, TRANSPORT_LINE_BUFFER);
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
  return find_line(self, error, length, line);
}  

static int
decode_packet(struct transport_read *self,
	      int *error, const char **msg,
	      uint32_t *seqno,
	      uint32_t *length_p, const uint8_t **data_p)
{
  uint32_t block_size = self->crypto ? self->crypto->block_size : 8;
  uint32_t mac_size = self->mac ? self->mac->mac_size : 0;

  uint32_t crypt_done = block_size - 5;
  uint32_t crypt_left = self->total_length - (decrypt_done + mac_size);

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
  self->start += total_length;
  self->length -= total_length;
  
  if (self->compression)
    fatal("Inflating not yet implemented.\n");

  *data_p = data;
  *length_p = length;

  return 1;
}

void
transport_new_keys(struct transport_read *self,
		   struct mac_instance *mac,
		   struct crypto_instance *crypto,
		   struct compress_instance *inflate)
{
  self->mac = mac;
  self->crypto = crypto;
  self->inflate = inflate;
}
		   
#define TRANSPORT_PACKET_BUFFER 1000

/* First reads the entire packet into the input_buffer, decrypting it
   in place. Next, reads the mac and verifies it. */
int
transport_read_packet(struct transport_read *self, int fd,
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

      res = read_some(self, fd, TRANSPORT_PACKET_BUFFER);

      if (res == 0)
	{
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
      if (self->length < block_size)
	return 0;

      if (self->crypto)
	{
	  CRYPT(self->crypto, block_size,
		self->input_buffer, self->start,
		self->input_buffer, self->start);
	}

      header = lsh_string_data(self->super.header);
      
      if (self->mac)
	{
	  uint8_t s[4];
	  WRITE_UINT32(s, self->sequence_number);
	  MAC_UPDATE(self->mac, 4, s);
	  MAC_UPDATE(self->mac, block_size, header);
	}
      
      packet_length = READ_UINT32(header);
      self->padding = header[4];

      if ( (self->padding < 4)
	   || (self->padding >= length) )
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

      res = read_some(self, fd, self->total_length + TRANSPORT_PACKET_BUFFER);

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
transport_read_init(struct transport_read *self)
{
  self->state = TRANSPORT_LINE;
  self->input_pos = self->output_pos = 0;
  self->seqno = 0;
}

void
transport_read_packet(struct transport_read *self)
{
  self->state = TRANSPORT_HEADER;
  self->block_size = 8;
}

int
transport_read_process(struct transport_read *self, uint32_t *done,
		       uint32_t length, const uint8_t *data)
{
  if (self->mode == TRANSPORT_LINE)
    {
      assert(self->output_pos < SSH_MAX_LINE);
      uint32_t left = SSH_MAX_LINE - self->output_pos;
      uint8_t *eol;
      if (length > left)
	length = left;

      eol = memchr(data, 0xa, length);
      if (!eol)
	{
	  if (length == left)
	    {
	      self->msg = "Line too long.";
	      return SSH_DISCONNECT_PROTOCOL_ERROR;
	    }
	  memcpy(self->output + self->output_pos, data, length);
	  self->output_pos += length;
	  *done = length;
	  return -1;
	}
      /* Length excluding linefeed. */
      length = eol - data;
      memcpy(self->output + self->output_pos, data, length);
      self->length = self->output_pos + length;
      if (self->length && self->output[self->length - 1] == 0xd)
	self->length--;

      *done = length + 1;
      self->output_pos = self->input_pos = 0;
      return 0;
    }
  else if (self->mode == TRANSPORT_HEADER)
}
#endif
