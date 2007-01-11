/* ssh_read.h
 *
 * Fairly general liboop-based packer reader.
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


#ifndef LSH_SSH_READ_H_INCLUDED
#define LSH_SSH_READ_H_INCLUDED

#include <oop.h>

#include "lsh.h"

enum ssh_read_status
{
  /* Read error, errno value stored in *error. */
  SSH_READ_IO_ERROR = -1,
  /* Protocol error, SSH_DISCONNECT reson code stored in *error and
     error message in *msg. */
  SSH_READ_PROTOCOL_ERROR = -2,
  /* End of file reached. */
  SSH_READ_EOF = 0,
  /* Packet/line read successfully. */
  SSH_READ_COMPLETE = 1,
  /* There's more data available for the next read. */
  SSH_READ_PENDING = 2,
  /* No more data available now, so read data should be delivered
     immediately. */
  SSH_READ_PUSH = 3,
};

#define GABA_DECLARE
# include "ssh_read.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name ssh_read_state)
     (vars
       (input_buffer string)
       (start . uint32_t)
       (length . uint32_t)

       (read_status . "enum ssh_read_status")))
*/

/* Attempts reading data, at most so that the input_buffer contains
   limit bytes. Returns -1 on error, 0 at EOF, and 1 for success. */

int
ssh_read_some(struct ssh_read_state *self, int fd, uint32_t limit);

void
init_ssh_read_state(struct ssh_read_state *self, uint32_t buffer_size);

#endif /* LSH_SSH_READ_H_INCLUDED */
