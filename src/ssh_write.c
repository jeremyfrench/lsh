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

/* Sending 5 packets at a time should be sufficient. */
#define N_IOVEC 5

void
init_ssh_write_state(struct ssh_write_state *self)
{
  string_queue_init(self->q);
  self->done = 0;
}

struct ssh_write_state *
make_ssh_write_state(void)
{
  NEW(ssh_write_state, self);
  init_ssh_write_state(self);
  return self;
}

static void *
oop_ssh_write(oop_source *source, int fd, oop_event event, void *state)
{
  struct iovec iv[N_IOVEC];
  struct lsh_string *first;
  unsigned n = 0;
  int res;
  
  FOR_STRING_QUEUE(&self->q, s)
    {
      iv[n].iov_base = lsh_string_data(s);
      iv[n].iov_len = lsh_string_length(s);

      if (++n == N_IOVEC)
	break;
    }
  assert(n > 0);
  assert(iv[0].iov_len > self->done);

  iv[0].iov_base += done;
  iv[0].iov_len -= done;

  do
    res = writev(fd, iv, n);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    {
      /* FIXME: We need an error callback */
      fatal("oop_ssh_write: writev failed: %e\n", errno);
    }
  else
    {
      unsigned i;
      assert(res > 0);
      for (i = 0; i < n && res >= iv[i].iov_len; i++)
	{
	  string_queue_remove_head(&self->q);
	  res -= iv[i].iov_len;
	}
      if (string_queue_is_empty(&self->q))
	{
	  assert(self->done == 0);
	  source->cancel_fd(source, fd, OOP_WRITE);
	}
      else
	self->done = res;
    }
  return OOP_CONTINUE;
}

static int
ssh_write_data(struct ssh_write_state *self,
	       oop_source *source, int fd,
	       struct lsh_string *data)
{
  if (string_queue_is_empty(&self->q))
    {
      uint32_t length = lsh_string_length(data);
      int res;

      assert(length);

      do
	res = write(fd, lsh_string_data(data), length);
      while (res < 0 && errno == EINTR);

      assert(res);

      if (res < 0)
	{
	  if (errno != EWOULDBLOCK)
	    return -1;

	  done = 0;
	start_queue:
	  string_queue_add_tail(&self->q, data);
	  source->on_fd(source, fd, OOP_WRITE, oop_ssh_write, self);
	  return 0;
	}
      else if (res == length)
	{
	  lsh_string_free(data);
	  return 1;
	}
      else
	{
	  /* Partial write */
	  done = res;
	  goto start_queue;
	}
    }
  else
    {
      string_queue_add_tail(&self->q, data);
      return 0;
    }
}
