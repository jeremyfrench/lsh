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

#include "transport.h"

#include "crypto.h"
#include "ssh.h"
#include "ssh_write.h"
#include "xalloc.h"

#include "transport_write.c.x"

/* GABA:
   (class
     (name transport_write_state)
     (super ssh_write_state)
     (vars     
       (mac object mac_instance)
       (crypto object crypto_instance)
       (deflate object compress_instance)
       (seqno . uint32_t)))
*/

/* When we have to send less than TRANSPORT_SMALL_PACKET, size is
   increased by padding with an SSH_MSG_IGNORE message. A single
   keystroke gives rise to a 10-byte payload, which will be
   encapsulated and padded to 24 bytes or 32 bytes, depending on the
   block size, and then the MAC (typically 16 or 20 bytes) is added to
   this, resulting in a packet in the range 40-52 bytes. */
#define TRANSPORT_SMALL_PACKET 60

#define TRANSPORT_MAX_BUFFER (10 * (SSH_MAX_PACKET + SSH_MAX_PACKET_FUZZ))

struct transport_write_state *
make_transport_write_state(void)
{
  NEW(transport_write_state, self);
  init_ssh_write_state(&self->super);
  self->mac = NULL;
  self->crypto = NULL;
  self->deflate = NULL;
  self->seqno = 0;

  return self;
}

/* Returns 1 on success, -1 on i/o error, -2 on buffer overflow, and 0
   if data is still buffered. */
int
transport_write_packet(struct transport_write_state *self, int fd, int flush,
		       struct lsh_string *packet, struct randomness *random)
{
  uint32_t length;
  int res;
  packet = encrypt_packet(packet,
			  self->deflate,
			  self->crypto,
			  self->mac,
			  random,
			  self->seqno++);

#if 0
  length = lsh_string_length(packet);
  
  if (flush && self->crypto
      && (length + self->super.size) < TRANSPORT_SMALL_PACKET)
    {
      uint8_t pad[TRANSPORT_SMALL_PACKET];
      uint32_t pad_length;
      uint32_t overhead_length;
      
      res = ssh_write(&self->super, fd, 0, packet);      
      if (res < 0)
	return res;

      assert(self->super.size < TRANSPORT_SMALL_PACKET);

      /* Desired packet length */
      pad_length = TRANSPORT_SMALL_PACKET - self->super.size;
      overhead_length = 14 + (self->mac ? self->mac->mac_size : 0);

      if (pad_length > overhead_length)
	{
	  pad_length -= overhead_length;
	  ASSERT(pad_length < sizeof(pad));
	  RANDOM(random, pad_length, pad);
	  packet = ssh_format("%c%s", SSH_MSG_IGNORE, pad_length, pad);
	}
      else
	packet = ssh_format("%c", SSH_MSG_IGNORE);

      packet = encrypt_packet(packet,
			      self->deflate,
			      self->crypto,
			      self->mac,
			      random,
			      self->seqno++);

      /* Won't quite work; we need more precise control over which
	 part of the packet is flushed. */      
    }
#endif
  res = ssh_write_data(&self->super, fd, flush, packet);
  if (res == 0 && self->super.size > TRANSPORT_MAX_BUFFER)
    return -2;
  else
    return res;
}

int
transport_write_line(struct transport_write_state *self,
		     int fd,
		     struct lsh_string *line)
{
  return ssh_write_data(&self->super, fd, 0, line);
}

int
transport_write_flush(struct transport_write_state *self,
		      int fd)
{
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
