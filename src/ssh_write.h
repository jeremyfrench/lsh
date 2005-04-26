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

#include "queue.h"

#define GABA_DECLARE
# include "ssh_write.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name ssh_write_state)
     (vars
       (buffer string)
       (start . uint32_t)
       (length . uint32_t)
       ; The preferred packet size, and amount of data we try to
       ; collect actually writing anything.
       (threshold . uint32_t)
       ; Amount of unimportant data at end of buffer
       (ignore . uint32_t)))
*/

/* Error codes are negative */
enum ssh_write_status
{
  /* I/O error (see errno) */
  SSH_WRITE_IO_ERROR = -1,
  /* Buffer grew too large */
  SSH_WRITE_OVERFLOW = -2,
  /* All buffered data (except ignore data) written successfully. */
  SSH_WRITE_COMPLETE = 1,
  /* Buffered data still pending; call ssh_write_flush. */
  SSH_WRITE_PENDING
};

enum ssh_write_flag
{
  SSH_WRITE_FLAG_PUSH = 1,
  SSH_WRITE_FLAG_IGNORE = 2,
};

void
init_ssh_write_state(struct ssh_write_state *self,
		     uint32_t buffer_size, uint32_t threshold);

struct ssh_write_state *
make_ssh_write_state(uint32_t buffer_size, uint32_t threshold);

/* If fd = -1, add data to buffer, don't write anything. Otherwise,
   attempt to write data if we have more than threshold, or the push flag is set. */
enum ssh_write_status
ssh_write_data(struct ssh_write_state *self,
	       int fd, enum ssh_write_flag flags,
	       uint32_t length, const uint8_t *data);

uint32_t
ssh_write_available(const struct ssh_write_state *self);

/* Try write some more data */
enum ssh_write_status
ssh_write_flush(struct ssh_write_state *self, int fd);

#endif /* LSH_SSH_WRITE_H_INCLUDED */
