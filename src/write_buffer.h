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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_WRITE_BUFFER_H_INCLUDED
#define LSH_WRITE_BUFFER_H_INCLUDED

#include "abstract_io.h"

#define CLASS_DECLARE
#include "write_buffer.h.x"
#undef CLASS_DECLARE

/* For the packet queue */
/* NOTE: No object header */
struct buffer_node
{
  struct buffer_node *next;
  struct buffer_node *prev;
  struct lsh_string *packet;
};

/* CLASS:
   (class
     (name write_buffer)
     (super abstract_write)
     (vars
       (block_size simple UINT32)
       (buffer space UINT8)        ; Size is twice the blocksize 
       (empty simple int)

       ; If non-zero, don't accept any more data. The i/o-channel
       ; should be closed once the current buffers are flushed. 
       (closed simple int)

       ;; (try_write simple int)

       (head special "struct buffer_node *"
                     #f do_free_buffer)
       (tail simple "struct buffer_node *")

       (pos simple UINT32)        ; Partial packet
       (partial string)

       (start simple UINT32)
       (end simple UINT32)))
*/

struct write_buffer *write_buffer_alloc(UINT32 size);
int write_buffer_pre_write(struct write_buffer *buffer);
void write_buffer_close(struct write_buffer *buffer);

#endif /* LSH_WRITE_BUFFER_H_INCLUDED */
