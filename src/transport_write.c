/* transport_write.c
 *
 * Writing the ssh transport protocol.
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
#include <errno.h>

#include "transport.h"

#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

/* When we have to send a small (less than super.threshold) amount of
   data, the size is increased by padding with an SSH_MSG_IGNORE
   message. A single keystroke gives rise to a 10-byte payload, which
   will be encapsulated and padded to 24 bytes or 32 bytes, depending
   on the block size, and then the MAC (typically 16 or 20 bytes) is
   added to this, resulting in a packet in the range 40-52 bytes.

   A small padding packet should be sufficient to get to a write size
   that is a multiple of 64 bytes. */
#define TRANSPORT_PADDING_SIZE 10

#define TRANSPORT_THRESHOLD 500

#define TRANSPORT_BUFFER_SIZE (10 * (SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ))

struct transport_write_state *
make_transport_write_state(void)
{
  NEW(transport_write_state, self);
  init_ssh_write_state(&self->super, TRANSPORT_BUFFER_SIZE);
  self->threshold = TRANSPORT_THRESHOLD;
  self->ignore = 0;

  self->mac = NULL;
  self->crypto = NULL;
  self->deflate = NULL;
  self->seqno = 0;

  return self;
}

static uint32_t
select_write_size(uint32_t length, uint32_t ignore, uint32_t threshold)
{
  if (length >= 8 * threshold)
    return 8 * threshold;
  else if (length >= threshold)
    return threshold;

  if (ignore)
    {
      /* Select a nice size in the interval length - ignore, length.
	 For now, prefer lengths that end with as many zeros as
	 possible */

      uint32_t no_ignore = length - ignore;
      uint32_t mask = ~0;

      while ((length & (mask << 1)) >= no_ignore)
	mask <<= 1;

      length = length & mask;            
    }
  return length;
}

static enum transport_write_status
update_status(struct transport_write_state *self, uint32_t done)
{
  if (done > 0)
    {
      if (self->super.length > self->ignore)
	/* FIXME: One could keep track of the push mark, and
	   return TRANSPORT_WRITE_COMPLETE when there's ignore
	   data and unpushed data in the buffer. */
	return TRANSPORT_WRITE_PENDING;
      else
	{
	  if (self->super.length < self->ignore)
	    self->ignore = self->super.length;
	    
	  return TRANSPORT_WRITE_COMPLETE;
	}
    }
  else switch(errno)
    {
    case EWOULDBLOCK:
      return TRANSPORT_WRITE_PENDING;
    case EOVERFLOW:
      return TRANSPORT_WRITE_OVERFLOW;
    default:
      return TRANSPORT_WRITE_IO_ERROR;
    }
}

static enum transport_write_status
write_data(struct transport_write_state *self, int fd,
	   enum transport_write_flag flags,
	   uint32_t length, const uint8_t *data)
{
  assert(fd >= 0);

  if (flags & TRANSPORT_WRITE_FLAG_IGNORE)
    self->ignore = self->ignore + length;
  else
    self->ignore = 0;

  if (! (flags & TRANSPORT_WRITE_FLAG_PUSH)
      && length + self->super.length < self->threshold)
    {
    enqueue:
      /* Just enqueue the data */
      if (!ssh_write_enqueue(&self->super, length, data))
	return TRANSPORT_WRITE_OVERFLOW;
      else
	return TRANSPORT_WRITE_COMPLETE;
    }
  else
    {
      /* Try a write call right away */
      uint32_t to_write;
      uint32_t done;
      
      to_write = select_write_size(self->super.length + length, self->ignore, self->threshold);
      if (!to_write)
	goto enqueue;

      done = ssh_write_data(&self->super, fd, to_write,
			    length, data);

      return update_status(self, done);
    }
}

static enum transport_write_status
write_flush(struct transport_write_state *self, int fd)
{
  uint32_t to_write;
  uint32_t done;
  
  if (self->super.length <= self->ignore)
    return TRANSPORT_WRITE_COMPLETE;

  to_write = select_write_size(self->super.length, self->ignore, self->threshold);  

  assert(to_write > 0);
  done = ssh_write_flush(&self->super, fd, to_write);

  return update_status(self, done);
}

static struct lsh_string *
make_ignore_packet(struct transport_write_state *self,
		   uint32_t length, struct randomness *random)
{
  uint32_t pad_start;      
  struct lsh_string *packet;
  
  packet = ssh_format("%c%r", SSH_MSG_IGNORE, length, &pad_start);
  lsh_string_write_random(packet, pad_start, random, length);

  packet = encrypt_packet(packet,
			  self->deflate,
			  self->crypto,
			  self->mac,
			  random,
			  self->seqno++);

  return packet;
}

enum transport_write_status
transport_write_packet(struct transport_write_state *self,
		       int fd, enum transport_write_flag flags,
		       struct lsh_string *packet, struct randomness *random)
{
  uint32_t length;
  uint8_t msg;
  
  enum transport_write_status status;

  assert(lsh_string_length(packet) > 0);
  if (lsh_string_data(packet)[0] == SSH_MSG_IGNORE)
    flags |= TRANSPORT_WRITE_FLAG_IGNORE;

  length = lsh_string_length(packet);
  assert(length > 0);

  msg = lsh_string_data(packet)[0];

  trace("Sending %T (%i) message, length %i\n", msg, msg, length);
  
  packet = encrypt_packet(packet,
			  self->deflate,
			  self->crypto,
			  self->mac,
			  random,
			  self->seqno++);

  length = lsh_string_length(packet);
  
  if ( (flags == TRANSPORT_WRITE_FLAG_PUSH) && self->crypto
       && (length + self->super.length) < self->threshold)
    {
      status = write_data(self, fd, 0, STRING_LD(packet));
      lsh_string_free(packet);

      if (status < 0)
	return status;

      packet = make_ignore_packet(self, TRANSPORT_PADDING_SIZE, random);

      flags |= TRANSPORT_WRITE_FLAG_IGNORE;
    }

  status = write_data(self, fd, flags, STRING_LD(packet));
  lsh_string_free(packet);

  return status;
}

enum transport_write_status
transport_write_line(struct transport_write_state *self,
		     int fd,
		     struct lsh_string *line)
{
  enum transport_write_status status;
  status = write_data(self, fd, TRANSPORT_WRITE_FLAG_PUSH, STRING_LD(line));
  lsh_string_free(line);
  return status;
}

enum transport_write_status
transport_write_flush(struct transport_write_state *self,
		      int fd, struct randomness *random)
{
  if (!self->ignore && self->crypto
      && self->super.length < self->threshold)
    {
      enum transport_write_status status;
      struct lsh_string *packet;

      packet = make_ignore_packet(self, TRANSPORT_PADDING_SIZE, random);
      status = write_data(self, fd, TRANSPORT_WRITE_FLAG_IGNORE, STRING_LD(packet));
      lsh_string_free(packet);

      if (status < 0)
	return status;
    }
      
  return write_flush(self, fd);
}

void
transport_write_new_keys(struct transport_write_state *self,
			 struct mac_instance *mac,
			 struct crypto_instance *crypto,
			 struct compress_instance *deflate)
{
  self->mac = mac;
  self->crypto = crypto;
  self->deflate = deflate;
}
