/* channel_io.h
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

#include "io.h"
#include "ssh_write.h"

struct ssh_channel;

#define GABA_DECLARE
# include "channel_io.h.x"
#undef GABA_DECLARE

/* GABA:
   (struct
     (name channel_read_state)
     (vars
       (fd . int)
       (active . int)
       (buffer string)))
*/

void
init_channel_read_state(struct channel_read_state *self, int fd,
			uint32_t buffer_size);

void
channel_read_state_close(struct channel_read_state *file);

uint32_t
channel_io_read(struct ssh_channel *channel,
		struct channel_read_state *file);

void
channel_io_start_read(struct ssh_channel *channel,
		      struct channel_read_state *file, oop_call_fd *f);

void
channel_io_stop_read(struct channel_read_state *file);

/* GABA:
   (struct
     (name channel_write_state)
     (vars
       (fd . int)
       (active . int)
       (state object ssh_write_state)))
*/

void
init_channel_write_state(struct channel_write_state *self, int fd,
			 uint32_t buffer_size);

void
channel_write_state_close(struct ssh_channel *channel,
			  struct channel_write_state *file);

void
channel_io_write(struct ssh_channel *channel,
		 struct channel_write_state *file,
		 oop_call_fd *f,
		 uint32_t length, const uint8_t *data);

void
channel_io_flush(struct ssh_channel *channel,
		 struct channel_write_state *file);

void
channel_io_start_write(struct ssh_channel *channel,
		       struct channel_write_state *file, oop_call_fd *f);

void
channel_io_stop_write(struct ssh_channel *channel,
		      struct channel_write_state *file);

