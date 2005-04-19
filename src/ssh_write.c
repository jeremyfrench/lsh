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

/* Sending 5 packets at a time should be sufficient. */
#define N_IOVEC 5

#define SSH_WRITE_SIZE 1000

void
init_ssh_write_state(struct ssh_write_state *self)
{
  string_queue_init(&self->q);
  self->done = 0;
}

struct ssh_write_state *
make_ssh_write_state(void)
{
  NEW(ssh_write_state, self);
  init_ssh_write_state(self);
  return self;
}

int
ssh_write_flush(struct ssh_write_state *self, int fd)
{
  struct iovec iv[N_IOVEC];
  unsigned n = 0;
  int res;

  if (string_queue_is_empty(&self->q))
    return 1;

  FOR_STRING_QUEUE(&self->q, s)
    {
      iv[n].iov_base = (char *) lsh_string_data(s);
      iv[n].iov_len = lsh_string_length(s);

      if (++n == N_IOVEC)
	break;
    }
  assert(n > 0);
  assert(iv[0].iov_len > self->done);

  iv[0].iov_base = (char *) iv[0].iov_base + self->done;
  iv[0].iov_len -= self->done;

  do
    res = writev(fd, iv, n);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    /* Let caller check for EWOULDBLOCK */
    return -1;

  else
    {
      uint32_t written;
      unsigned i;
      
      assert(res > 0);
      written = res;
      self->size -= written;
      
      for (i = 0; i < n && written >= iv[i].iov_len; i++)
	{
	  string_queue_remove_head(&self->q);
	  written -= iv[i].iov_len;
	}
      if (string_queue_is_empty(&self->q))
	{
	  assert(self->done == 0);
	  return 1;
	}
      else
	{
	  self->done = written;
	  return 0;
	}
    }
}

int
ssh_write_data(struct ssh_write_state *self,
	       int fd, int flush,
	       struct lsh_string *data)
{
  string_queue_add_tail(&self->q, data);
  self->size += lsh_string_length(data);
  if (flush || self->size >= SSH_WRITE_SIZE)
    return ssh_write_flush(self, fd);
  else
    return 0;
}
