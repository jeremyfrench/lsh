/* ssh_read.c
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
#include <string.h>

#include "ssh_read.h"

#include "io.h"
#include "lsh_string.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "ssh_read.h.x"
#undef GABA_DEFINE

int
ssh_read_some(struct ssh_read_state *self, int fd, uint32_t limit)
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

  res = lsh_string_read(self->input_buffer, self->start + self->length, fd, left);

  if (res < 0)
    return -1;
  else if (res == 0)
    return 0;

  self->length += res;

  self->read_status = (res < left || !io_readable_p(fd))
    ? SSH_READ_PUSH : SSH_READ_PENDING;

  return 1;
}

void
init_ssh_read_state(struct ssh_read_state *self, uint32_t buffer_size)
{
  self->input_buffer = lsh_string_alloc(buffer_size);
  self->start = self->length = 0;
  self->read_status = SSH_READ_PUSH;
}
