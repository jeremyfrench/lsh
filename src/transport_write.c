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

#include "transport.h"

#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "ssh.h"
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
  init_ssh_write_state(&self->super,
		       TRANSPORT_BUFFER_SIZE, TRANSPORT_THRESHOLD);
  self->mac = NULL;
  self->crypto = NULL;
  self->deflate = NULL;
  self->seqno = 0;

  return self;
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

enum ssh_write_status
transport_write_packet(struct transport_write_state *self,
		       int fd, enum ssh_write_flag flags,
		       struct lsh_string *packet, struct randomness *random)
{
  uint32_t length;
  enum ssh_write_status status;

  assert(lsh_string_length(packet) > 0);
  if (lsh_string_data(packet)[0] == SSH_MSG_IGNORE)
    flags |= SSH_WRITE_FLAG_IGNORE;

  packet = encrypt_packet(packet,
			  self->deflate,
			  self->crypto,
			  self->mac,
			  random,
			  self->seqno++);

  length = lsh_string_length(packet);
  
  if ( (flags == SSH_WRITE_FLAG_PUSH) && self->crypto
       && (length + self->super.length) < self->super.threshold)
    {
      status = ssh_write_data(&self->super, fd, 0, STRING_LD(packet));
      lsh_string_free(packet);

      if (status < 0)
	return status;

      packet = make_ignore_packet(self, TRANSPORT_PADDING_SIZE, random);

      flags |= SSH_WRITE_FLAG_IGNORE;
    }

  status = ssh_write_data(&self->super, fd, flags, STRING_LD(packet));
  lsh_string_free(packet);

  return status;
}

enum ssh_write_status
transport_write_line(struct transport_write_state *self,
		     int fd,
		     struct lsh_string *line)
{
  enum ssh_write_status status;
  status = ssh_write_data(&self->super, fd, 0, STRING_LD(line));
  lsh_string_free(line);
  return status;
}

enum ssh_write_status
transport_write_flush(struct transport_write_state *self,
		      int fd, struct randomness *random)
{
  if (!self->super.ignore && self->crypto
      && self->super.length < self->super.threshold)
    {
      enum ssh_write_status status;
      struct lsh_string *packet;

      packet = make_ignore_packet(self, TRANSPORT_PADDING_SIZE, random);
      status = ssh_write_data(&self->super, fd,
			      SSH_WRITE_FLAG_IGNORE, STRING_LD(packet));
      lsh_string_free(packet);

      if (status < 0)
	return status;
    }
      
  return ssh_write_flush(&self->super, fd);
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
