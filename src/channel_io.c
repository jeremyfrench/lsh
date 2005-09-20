/* channel_io.c
 *
 * Helper functions for channels bound to files.
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

#include "channel_io.h"

#include "channel.h"
#include "io.h"
#include "lsh_string.h"
#include "werror.h"

#define GABA_DEFINE
# include "channel_io.h.x"
#undef GABA_DEFINE

void
init_channel_read_state(struct channel_read_state *self, int fd,
			uint32_t buffer_size)
{
  self->fd = fd;
  self->active = 0;
  self->buffer = lsh_string_alloc(buffer_size);
}

void
channel_read_state_close(struct channel_read_state *file)
{
  if (file->fd < 0)
    return;

  io_close_fd(file->fd);
  file->fd = -1;
}

enum channel_io_status
channel_io_read(struct ssh_channel *channel,
		struct channel_read_state *file, uint32_t *done)
{
  uint32_t to_read;
  int res;

  assert(channel->sources);
  
  /* There are three numbers that limit the amount of data we can read:
   *
   *   1 The current send_window_size.
   *   2 The send_max_packet size for the channel.
   *   3 (The maximum size for a complete packet SSH_MAX_PACKET)
   *
   * We don't enforce (3) here, but assume that if the remote end has
   * given us a huge send_max_packet, it will also handle huge ssh
   * packets.
   *
   * For channels that are forwarded via a gateway, we do need to care
   * about (3), but that is done by the gatewaying code adjusting the
   * send_max_packet. */

  to_read = lsh_string_length(file->buffer);

  if (to_read > channel->send_window_size)
    to_read = channel->send_window_size;

  if (to_read > channel->send_max_packet)
    to_read = channel->send_max_packet;

  if (!to_read)
    {
      /* Out of window space, so stop reading. */
      channel_io_stop_read(file);
      *done = 0;
      return CHANNEL_IO_OK;
    }

  res = lsh_string_read(file->buffer, 0, file->fd, to_read);

  if (res < 0)
    {
      werror("reading on channel fd %d failed: %e.\n", file->fd, errno);

      channel_close(channel);
      return CHANNEL_IO_ERROR;
    }
  else if (res == 0)
    {
      assert(channel->sources);
      if (!--channel->sources)
	channel_eof(channel);

      channel_io_stop_read(file);

      *done = 0;
      return CHANNEL_IO_EOF;
    }

  *done = res;
  return CHANNEL_IO_OK;
}

void
channel_io_start_read(struct ssh_channel *channel,
		      struct channel_read_state *file, oop_call_fd *f)
{
  if (file->fd >= 0 && !file->active)
    {
      file->active = 1;
      global_oop_source->on_fd(global_oop_source, file->fd,
			       OOP_READ, f, channel);
    }
}

void
channel_io_stop_read(struct channel_read_state *file)
{
  if (file->active)
    {
      file->active = 0;
      global_oop_source->cancel_fd(global_oop_source, file->fd, OOP_READ);
    }
}

void
init_channel_write_state(struct channel_write_state *self, int fd,
			uint32_t buffer_size)
{
  self->fd = fd;
  self->active = 0;
  self->state = make_ssh_write_state(buffer_size);
}

void
channel_write_state_close(struct ssh_channel *channel,
			  struct channel_write_state *file)
{
  if (file->fd < 0)
    return;

  io_close_fd(file->fd);
  file->fd = -1;
  
  assert(channel->sinks);
  channel->sinks--;
  channel_maybe_close(channel);
}

enum channel_io_status
channel_io_write(struct ssh_channel *channel,
		 struct channel_write_state *file,
		 oop_call_fd *f,
		 uint32_t length, const uint8_t *data)
{
  uint32_t done;

  done = ssh_write_data(file->state, file->fd, 0, length, data);
  if (done > 0 || errno == EWOULDBLOCK)
    {
      channel_adjust_rec_window(channel, done);

      if (file->state->length)
	{
	  channel_io_start_write(channel, file, f);
	  return CHANNEL_IO_OK;
	}
      else
	return channel_io_stop_write(channel, file);
    }
  else
    {
      werror("write failed on channel write fd %d: %e.\n", file->fd, errno);

      channel_close(channel);
      return CHANNEL_IO_ERROR;
    }
}

enum channel_io_status
channel_io_flush(struct ssh_channel *channel,
		 struct channel_write_state *file)
{
  uint32_t done = ssh_write_flush(file->state, file->fd, 0);
  if (done > 0)
    {
      channel_adjust_rec_window(channel, done);
      if (!file->state->length)
	return channel_io_stop_write(channel, file);
    }
  else if (errno != EWOULDBLOCK)
    {
      werror("Write failed on channel write fd %d: %e.\n", file->fd, errno);

      channel_close(channel);
      return CHANNEL_IO_ERROR;
    }
  return CHANNEL_IO_OK;      
}

void
channel_io_start_write(struct ssh_channel *channel,
		       struct channel_write_state *file, oop_call_fd *f)
{
  if (!file->active)
    {
      file->active = 1;
      global_oop_source->on_fd(global_oop_source, file->fd, OOP_WRITE,
			       f, channel);
    }
}

enum channel_io_status
channel_io_stop_write(struct ssh_channel *channel,
		      struct channel_write_state *file)
{
  if (file->active)
    {
      file->active = 0;
      global_oop_source->cancel_fd(global_oop_source, file->fd, OOP_WRITE);
    }

  return (channel->flags & CHANNEL_RECEIVED_EOF) ? CHANNEL_IO_EOF : CHANNEL_IO_OK;
}
