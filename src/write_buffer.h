/* write_buffer.h
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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

#ifndef LSH_WRITE_BUFFER_H_INCLUDED
#define LSH_WRITE_BUFFER_H_INCLUDED

#include "abstract_io.h"
#include "queue.h"

#define GABA_DECLARE
#include "write_buffer.h.x"
#undef GABA_DECLARE

/* For the packet queue */
/* NOTE: No object header */
struct buffer_node
{
  struct lsh_queue_node header;
  struct lsh_string *packet;
};

/* GABA:
   (class
     (name write_buffer)
     (super abstract_write)
     (vars
       (block_size simple UINT32)
       (buffer space UINT8)        ; Size is twice the blocksize 
       (empty simple int)

       ; Total amount of data currently in the buffer)
       (length . UINT32)
       
       ; If non-zero, don't accept any more data. The i/o-channel
       ; should be closed once the current buffers are flushed. 
       (closed simple int)

       ;; (try_write simple int)

       (q special-struct "struct lsh_queue"
                     #f do_free_buffer)

       (pos simple UINT32)        ; Partial packet
       (partial string)

       (start simple UINT32)
       (end simple UINT32)))
*/

struct write_buffer *write_buffer_alloc(UINT32 size);
int write_buffer_pre_write(struct write_buffer *buffer);
void write_buffer_consume(struct write_buffer *buffer, UINT32 size);
void write_buffer_close(struct write_buffer *buffer);

#endif /* LSH_WRITE_BUFFER_H_INCLUDED */
