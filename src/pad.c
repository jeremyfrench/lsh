/* pad.c
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

#include <assert.h>

#include "pad.h"
#include "randomness.h"
#include "xalloc.h"

static int do_pad(struct abstract_write **w,
		  struct lsh_string *packet)
{
  struct packet_pad *closure
    = (struct packet_pad *) *w;
  
  UINT32 new_size;
  UINT8 padding;

  struct lsh_string *new;

  new_size = 1 + closure->block_size
    * ( (8 + packet->length) / closure->block_size);

  padding = new_size - packet->length - 5;
  assert(padding >= 4);

  /* FIXME: Use ssh_format() */
  new = lsh_string_alloc(new_size);

  WRITE_UINT32(new->data, new_size - 4);
  new->data[4] = padding;
  
  memcpy(new->data + 5, packet->data, packet->length);
  RANDOM(closure->random, padding, new->data + 5 + packet->length);
  
  lsh_string_free(packet);

  return A_WRITE(closure->super.next, new);
}
  
struct abstract_write *
make_packet_pad(struct abstract_write *continuation,
		unsigned block_size,
		struct randomness *random)
{
  struct packet_pad *closure = xalloc(sizeof(struct packet_pad));

  closure->super.super.write = do_pad;
  closure->super.next = continuation;
  closure->block_size = block_size;
  closure->random = random;

  return &closure->super.super;
}
