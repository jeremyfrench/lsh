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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

#include <unistd.h>

#include <sys/uio.h>

#include "ssh_write.h"

#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "ssh_write.h.x"
#undef GABA_DEFINE

/* Pass at most this amount of data at once to write/writev */
#define WRITE_MAX 0x4000

void
init_ssh_write_state(struct ssh_write_state *self,
		     uint32_t buffer_size)
{
  self->buffer = lsh_string_alloc(buffer_size);
  self->start = self->length = 0;
}

struct ssh_write_state *
make_ssh_write_state(uint32_t buffer_size)
{
  NEW(ssh_write_state, self);
  init_ssh_write_state(self, buffer_size);
  return self;
}

uint32_t
ssh_write_flush(struct ssh_write_state *self, int fd, uint32_t to_write)
{
  const uint8_t *buffer;
  int res;

  if (!to_write)
    to_write = MIN(self->length, WRITE_MAX);

  assert(to_write > 0);
  assert(to_write <= self->length);
  
  buffer = lsh_string_data(self->buffer) + self->start;

  do
    res = write(fd, buffer, to_write);
  while (res < 0 && errno == EINTR);
  
  if (res < 0)
    return 0;

  self->start += res;
  self->length -= res;
  
  return res;
}

int
ssh_write_enqueue(struct ssh_write_state *self,
		  uint32_t length, const uint8_t *data)
{      
  uint32_t size = lsh_string_length(self->buffer);

  if (length + self->length > size)
    return 0;
  if (length + self->length + self->start > size)
    {
      lsh_string_move(self->buffer, 0, self->length, self->start);
      self->start = 0;
    }

  lsh_string_write(self->buffer, self->start + self->length,
		   length, data);
  self->length += length;

  return 1;
}

uint32_t
ssh_write_data(struct ssh_write_state *self,
	       int fd, uint32_t to_write,
	       uint32_t length, const uint8_t *data)
{
  const uint8_t *buffer;
  uint32_t done;
  
  if (!to_write)
    {
      to_write = self->length + length;
      if (to_write > WRITE_MAX)
	to_write = WRITE_MAX;
    }

  assert(to_write > 0);

  buffer = lsh_string_data(self->buffer) + self->start;

  if (to_write <= self->length)
    {
      int res;
      do
	res = write(fd, buffer, to_write);
      while (res < 0 && errno == EINTR);

      if (res < 0)
	{
	io_error:
	  if (length > 0 && !ssh_write_enqueue(self, length, data))
	    errno = EOVERFLOW;
	  
	  return 0;
	}
      
      self->length -= res;
      self->start += res;

      done = res;
    }
  else if (self->length == 0)
    {
      int res;
      do
	res = write(fd, data, to_write);
      while (res < 0 && errno == EINTR);

      if (res < 0)
	goto io_error;

      length -= res;
      data += res;

      done = res;
    }
  else
    {
      struct iovec iv[2];
      int res;
      iv[0].iov_base = (char *) buffer;
      iv[0].iov_len = self->length;
      iv[1].iov_base = (char *) data;
      iv[1].iov_len = to_write - self->length;
	  
      do
	res = writev(fd, iv, 2);
      while (res < 0 && errno == EINTR);

      if (res < 0)
	goto io_error;

      done = res;
      if (done < self->length)
	{
	  self->length -= done;
	  self->start += done;
	}
      else
	{
	  uint32_t data_done = done - self->length;
	  self->length = self->start = 0;

	  data += data_done;
	  length -= data_done;
	}
    }
  assert(done > 0);
  
  if (length > 0 && !ssh_write_enqueue(self, length, data))
    {
      errno = EOVERFLOW;
      return 0;
    }

  return done;    
}      

uint32_t
ssh_write_available(const struct ssh_write_state *self)
{
  uint32_t size = lsh_string_length(self->buffer);
  assert(self->length <= size);
  return size - self->length;
}
