/* channel_forward.h
 *
 * General channel type for forwarding data to an fd
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2001 Balázs Scheidler, Niels Möller
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

#ifndef LSH_CHANNEL_FORWARD_H_INCLUDED
#define LSH_CHANNEL_FORWARD_H_INCLUDED

#include "channel.h"
#include "channel_io.h"

#define GABA_DECLARE
#include "channel_forward.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name channel_forward)
     (super ssh_channel)
     (vars
       ; We have to be careful, since both structs use the same fd
       (read struct channel_read_state)
       (write struct channel_write_state)))
*/

void
init_channel_forward(struct channel_forward *self,
		     int fd, uint32_t write_buffer_size,
		     void (*event)(struct ssh_channel *, enum channel_event));

struct channel_forward *
make_channel_forward(int fd, uint32_t write_buffer_size);

void
channel_forward_start_io(struct channel_forward *channel_forward);

void
channel_forward_start_read(struct channel_forward *channel);

void
channel_forward_write(struct channel_forward *self,
		      uint32_t length, const uint8_t *data);

void
channel_forward_shutdown(struct channel_forward *self);

#endif /* LSH_CHANNEL_FORWARD_H_INCLUDED */

