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

struct ssh_read_state;

#include <oop.h>

#include "lsh.h"

#define GABA_DECLARE
# include "ssh_read.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name header_callback)
     (vars
       (process method "struct lsh_string *"
                       "struct ssh_read_state *" "uint32_t *done")))
*/

#define HEADER_CALLBACK(c, s, p) \
((c)->process((c), (s), (p)))

/* GABA:
   (class
     (name ssh_read_state)
     (vars
       (pos . uint32_t)
       
       ; Fix buffer space of size SSH_MAX_BLOCK_SIZE       
       (header string)
       ; Current header length
       (header_length . uint32_t);
       
       ; The line or packet being read
       (data string)

       ; Called when header is read. It has total responsibility for
       ; setting up the next state.
       (process object header_callback)
       ; Called for each complete line or packet
       (handler object abstract_write)
       (e object exception_handler)))
*/  

void
ssh_read_line(struct ssh_read_state *self, uint32_t max_length,
	      oop_source *source, int fd,
	      struct abstract_write *handler);

void
ssh_read_header(struct ssh_read_state *self,
		oop_source *source, int fd,
		struct abstract_write *handler);

void
init_ssh_read_state(struct ssh_read_state *state,
		    uint32_t max_header, uint32_t header_length,
		    struct header_callback *process,
		    struct exception_handler *e);

struct ssh_read_state *
make_ssh_read_state(uint32_t max_header, uint32_t header_length,
		    struct header_callback *process,
		    struct exception_handler *e);

#endif /* LSH_SSH_READ_H_INCLUDED */
