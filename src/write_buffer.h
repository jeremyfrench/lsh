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

/* For the packet queue */
struct node
{
  struct lsh_object header;
  
  struct node *next;
  struct node *prev;
  struct lsh_string *packet;
};

struct write_buffer
{
  struct abstract_write super;
  
  UINT32 block_size;

  int empty;
  
#if 0
  int try_write;
#endif
  
  struct node *head;
  struct node *tail;

  UINT32 pos; /* Partial packet */
  struct lsh_string *partial;

  UINT32 start;
  UINT32 end;
  UINT8 buffer[1]; /* Real size is twice the blocksize */
};

#if 0
struct write_callback
{
  struct callback c;
  struct write_buffer buffer;
};
#endif

struct write_buffer *write_buffer_alloc(UINT32 size);
int write_buffer_pre_write(struct write_buffer *buffer);

#endif /* LSH_WRITE_BUFFER_H_INCLUDED */
