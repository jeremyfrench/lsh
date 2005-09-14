/* ssh_write.h
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

#ifndef LSH_SSH_WRITE_H_INCLUDED
#define LSH_SSH_WRITE_H_INCLUDED

#include "lsh.h"

#define GABA_DECLARE
# include "ssh_write.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name ssh_write_state)
     (vars
       (buffer string)
       (start . uint32_t)
       (length . uint32_t)))
*/


void
init_ssh_write_state(struct ssh_write_state *self,
		     uint32_t buffer_size);

struct ssh_write_state *
make_ssh_write_state(uint32_t buffer_size);

/* Adds data to the buffer. Returns 1 on success, 0 if there's no
   space. In the latter case, the buffer is unmodified. */
int
ssh_write_enqueue(struct ssh_write_state *self,
		  uint32_t length, const uint8_t *data);

/* Attempts to write some data. Data that cannot be written
   immediately is buffered. If to_write is non-zero, it gives the
   desired block size. On success, returns the amount of data actually
   written (and not just added to the buffer). On failure, returns 0
   and sets errno.

   EOVERFLOW is used to indicate that the buffer is full, and if this
   happens, data may or may not have been written, so the state of the
   object is not well defined. */
uint32_t
ssh_write_data(struct ssh_write_state *self,
	       int fd, uint32_t to_write,
	       uint32_t length, const uint8_t *data);

/* Try write some of the buffered data. Buffer must be non-empty. On
   success, returns amount written. On error, returns 0 and sets
   errno. to_write have the same meaning as for ssh_write_data. */
uint32_t
ssh_write_flush(struct ssh_write_state *self, int fd, uint32_t to_write);

uint32_t
ssh_write_available(const struct ssh_write_state *self);

#endif /* LSH_SSH_WRITE_H_INCLUDED */
