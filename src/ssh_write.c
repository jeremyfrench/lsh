/* ssh_write.c
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

#include "ssh_write.h"

#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "ssh_write.h.x"
#undef GABA_DEFINE

void
init_ssh_write_state(struct ssh_write_state *self,
		     uint32_t buffer_size, uint32_t threshold)
{
  self->buffer = lsh_string_alloc(buffer_size);
  self->start = self->length = self->ignore = 0;
  self->threshold = threshold;
}

struct ssh_write_state *
make_ssh_write_state(uint32_t buffer_size, uint32_t threshold)
{
  NEW(ssh_write_state, self);
  init_ssh_write_state(self, buffer_size, threshold);
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
  
enum ssh_write_status
ssh_write_flush(struct ssh_write_state *self, int fd)
{
  const uint8_t *data;
  uint32_t length;
  int res;

  if (self->length <= self->ignore)
    return SSH_WRITE_COMPLETE;

  length = select_write_size(self->length, self->ignore, self->threshold);  
  data = lsh_string_data(self->buffer);

  do
    res = write(fd, data + self->start, length);
  while (res < 0 && errno == EINTR);
  
  if (res < 0)
    /* Let caller check for EWOULDBLOCK, if approproate */
    return SSH_WRITE_IO_ERROR;

  assert(res > 0);
  self->start += res;
  self->length -= res;

  if (self->length <= self->ignore)
    {
      self->ignore = self->length;
      return SSH_WRITE_COMPLETE;
    }
  return SSH_WRITE_PENDING;
}

static enum ssh_write_status
enqueue(struct ssh_write_state *self,
	enum ssh_write_flag flags,
	uint32_t length, const uint8_t *data)
{      
  uint32_t size = lsh_string_length(self->buffer);

  if (length + self->length > size)
    return SSH_WRITE_OVERFLOW;
  if (length + self->length + self->start > size)
    {
      lsh_string_move(self->buffer, 0, self->length, self->start);
      self->start = 0;
    }

  lsh_string_write(self->buffer, self->start + self->length,
		   length, data);
  self->length += length;

  if (flags && SSH_WRITE_FLAG_IGNORE)
    self->ignore += length;
  else
    self->ignore = 0;

  if (self->length <= self->ignore)
    return SSH_WRITE_COMPLETE;
  else
    return SSH_WRITE_PENDING;
}

enum ssh_write_status
ssh_write_data(struct ssh_write_state *self,
	       int fd, enum ssh_write_flag flags,
	       uint32_t length, const uint8_t *data)
{
  if (fd < 0)
    return enqueue(self, flags, length, data);

  if ( (flags & SSH_WRITE_FLAG_PUSH)
       || length + self->length >= self->threshold)
    {
      /* Try a write call right away */
      uint32_t to_write;
      const uint8_t *buffer;
      uint32_t ignore;
      int res;
      
      if (flags & SSH_WRITE_FLAG_IGNORE)
	ignore = self->ignore + length;
      else
	ignore = 0;

      to_write = select_write_size(self->length + length, ignore, self->threshold);

      /* Can happen only if both SSH_WRITE_FLAG_IGNORE and
	 SSH_WRITE_FLAG_PUSH is set */
      if (!to_write)
	return enqueue(self, flags, length, data);	

      buffer = lsh_string_data(self->buffer) + self->start;

      if (to_write <= self->length)
	{
	  do
	    res = write(fd, buffer, to_write);
	  while (res < 0 && errno == EINTR);

	  if (res < 0)
	    return SSH_WRITE_IO_ERROR;

	  self->length -= res;
	  self->start += res;
	}
      else if (self->length == 0)
	{
	  do
	    res = write(fd, data, to_write);
	  while (res < 0 && errno == EINTR);

	  if (res < 0)
	    return SSH_WRITE_IO_ERROR;
	  length -= res;
	  data += res;
	}
      else
	{
	  struct iovec iv[2];
	  iv[0].iov_base = (char *) buffer;
	  iv[0].iov_len = self->length;
	  iv[1].iov_base = (char *) data;
	  iv[1].iov_len = to_write - self->length;
	  uint32_t done;
	  
	  do
	    res = writev(fd, iv, 2);
	  while (res < 0 && errno == EINTR);

	  if (res < 0)
	    return SSH_WRITE_IO_ERROR;

	  done = res;
	  if (done < self->length)
	    {
	      self->length -= done;
	      self->start += done;
	    }
	  else
	    {
	      done -= self->length;
	      self->length = self->start = self->ignore = 0;

	      data += done;
	      length -= done;
	    }
	}
    }
  return enqueue(self, flags, length, data);
}      
