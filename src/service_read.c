/* service_read.c
 *
 * oop-based reader for the local communication.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Niels Möller
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
#include <errno.h>

/* For ioctl and FIONREAD */
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <nettle/macros.h>

#include "service.h"

#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "service_read.c.x"

/* How much data to read ahead */
#define SERVICE_READ_AHEAD 1000

#define SERVICE_HEADER_SIZE 8

/* GABA:
   (class
     (name service_read_state)
     (super ssh_read_state)
     (vars
       ; Zero if we haven't processed the header yet
       (packet_length . uint32_t)
       (seqno . uint32_t)))
*/

struct service_read_state *
make_service_read_state(void)
{
  NEW(service_read_state, self);
  init_ssh_read_state(&self->super, SSH_MAX_PACKET + SERVICE_READ_AHEAD);

  self->packet_length = 0;
  
  return self;
}

enum ssh_read_status
service_read_packet(struct service_read_state *self, int fd,
		    const char **msg,
		    uint32_t *seqno,
		    uint32_t *length, const uint8_t **packet)
{
  if (self->packet_length == 0)
    {  
      const uint8_t *header;

      if (self->super.length < SERVICE_HEADER_SIZE)
	{
	  int res;
      
	  if (fd < 0)
	    return self->super.read_status;

	  res = ssh_read_some(&self->super, fd, SERVICE_READ_AHEAD);

	  fd = -1;

	  if (res == 0)
	    {
	      if (self->super.length == 0)
		return SSH_READ_EOF;
	      else
		{
		  *msg = "Unexpected EOF";
		  return SSH_READ_PROTOCOL_ERROR;
		}
	    }
	  else if (res < 0)
	    {
	      if (errno == EWOULDBLOCK)
		return SSH_READ_PUSH;

	      return SSH_READ_IO_ERROR;
	    }
	  if (self->super.length < SERVICE_HEADER_SIZE)
	    return self->super.read_status;
	}

      /* Got packet header. Parse it. */      
      assert(self->super.length >= SERVICE_HEADER_SIZE);

      header = lsh_string_data(self->super.input_buffer) + self->super.start;

      self->seqno = READ_UINT32(header);
      self->packet_length = READ_UINT32(header + 4);

      if (!self->packet_length)
	{
	  *msg = "Received empty packet";
	  return SSH_READ_PROTOCOL_ERROR;	  
	}
      else if (self->packet_length > SSH_MAX_PACKET)
	{
	  *msg = "Packet too large";
	  return SSH_READ_PROTOCOL_ERROR;
	}

      self->super.start += SERVICE_HEADER_SIZE;
      self->super.length -= SERVICE_HEADER_SIZE;
    }
  if (self->super.length < self->packet_length)
    {
      int res;
      
      if (fd < 0)
	return self->super.read_status;

      res = ssh_read_some(&self->super, fd, self->packet_length + SERVICE_READ_AHEAD);

      if (res == 0)
	{
	  *msg = "Unexpected EOF";
	  return SSH_READ_PROTOCOL_ERROR;
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK)
	    return SSH_READ_PUSH;

	  return SSH_READ_IO_ERROR;
	}

      if (self->super.length < self->packet_length)
	return self->super.read_status;
    }
  *length = self->packet_length;
  *packet = lsh_string_data(self->super.input_buffer) + self->super.start;
  *seqno = self->seqno;
  
  self->super.start += self->packet_length;
  self->super.length -= self->packet_length;
  self->packet_length = 0;

  return SSH_READ_COMPLETE;
}
