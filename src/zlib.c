/* zlib.c
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

#include "zlib.h"

static int do_deflate(struct abstract_write **c,
		      struct lsh_string *packet)
{
  struct zlib_processor *closure = (struct zlib_processor *) *c;
  
  struct lsh_string *new;

  /* call deflate, copy into new packet */

  new = lsh_string_alloc(...);
  lsh_string_free(packet);
  
  return apply_processor(closure->c->next, new);  
}

struct abstract_write *make_packet_zlib(abstract_write *continuation,
					int level)
{
  struct debug_processor *closure = xalloc(sizeof(struct zlib_processor));

  closure->super.super.write = do_deflate;
  closure->c->next = continuation;
  /* inititialize closure->zstream */

  return &closure->super.super;
}
