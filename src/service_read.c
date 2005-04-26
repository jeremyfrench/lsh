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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
     (vars
       (input_buffer string)
       (start . uint32_t)
       (length . uint32_t)

       (read_status . "enum service_read_status")
       (packet_length . uint32_t)
       (seqno . uint32_t)))
*/

struct service_read_state *
make_service_read_state(void)
{
  NEW(service_read_state, self);
  self->input_buffer = lsh_string_alloc(SSH_MAX_PACKET + SERVICE_READ_AHEAD);
  self->start = self->length = 0;

  self->read_status = SERVICE_READ_PUSH;
  self->packet_length = 0;
  
  return self;
}

/* FIXME: Duplicated in transport_read.c */
static int
readable_p(int fd)
{
  /* FIXME: What's the proper type for FIONREAD? And where's FIONREAD
     documented??? Is it better to use poll/select? */
  long nbytes = 0;
  if (ioctl(fd, FIONREAD, &nbytes) < 0)
    {
      debug("ioctl FIONREAD failed: %e\n", errno);
      return 0;
    }
  return nbytes != 0;
}

/* FIXME: Duplicated in transport_read.c */
/* Returns -1 on error, 0 at EOF, and 1 for success. */
static int
read_some(struct service_read_state *self, int fd, uint32_t limit)
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
  do
    res = lsh_string_read(self->input_buffer, self->start + self->length, fd, left);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    return -1;
  else if (res == 0)
    return 0;

  self->length += res;

  self->read_status = (res < left || !readable_p(fd))
    ? SERVICE_READ_PUSH : SERVICE_READ_PENDING;

  return 1;
}

enum service_read_status
service_read_packet(struct service_read_state *self, int fd,
		    const char **msg,
		    uint32_t *seqno,
		    uint32_t *length, const uint8_t **packet)
{
  if (self->length < SERVICE_HEADER_SIZE)
    {
      int res;
      
      if (fd < 0)
	return self->read_status;

      res = read_some(self, fd, SERVICE_READ_AHEAD);

      fd = -1;

      if (res == 0)
	{
	  if (self->length == 0)
	    return SERVICE_READ_EOF;
	  else
	    {
	      *msg = "Unexpected EOF";
	      return SERVICE_READ_PROTOCOL_ERROR;
	    }
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK)
	    return SERVICE_READ_PUSH;

	  return SERVICE_READ_IO_ERROR;
	}
      if (self->length < SERVICE_HEADER_SIZE)
	return self->read_status;
    }
  assert(self->length >= SERVICE_HEADER_SIZE);

  if (self->packet_length == 0)
    {
      const uint8_t *header;

      /* Process header */
      header = lsh_string_data(self->input_buffer) + self->start;

      self->seqno = READ_UINT32(header);
      self->packet_length = READ_UINT32(header + 4);

      if (self->packet_length > SSH_MAX_PACKET)
	{
	  *msg = "Packet too large";
	  return SERVICE_READ_PROTOCOL_ERROR;
	}

      self->start += SERVICE_HEADER_SIZE;
      self->length -= SERVICE_HEADER_SIZE;
    }
  if (self->length < self->packet_length)
    {
      int res;
      
      if (fd < 0)
	return self->read_status;

      res = read_some(self, fd, self->packet_length + SERVICE_READ_AHEAD);

      if (res == 0)
	{
	  *msg = "Unexpected EOF";
	  return SERVICE_READ_PROTOCOL_ERROR;
	}
      else if (res < 0)
	{
	  if (errno == EWOULDBLOCK)
	    return SERVICE_READ_PUSH;

	  return SERVICE_READ_IO_ERROR;
	}

      if (self->length < self->packet_length)
	return self->read_status;
    }
  *length = self->packet_length;
  *packet = lsh_string_data(self->input_buffer) + self->start;
  *seqno = self->seqno;
  
  self->start += self->packet_length;
  self->length -= self->packet_length;
  self->packet_length = 0;

  return SERVICE_READ_COMPLETE;
}
