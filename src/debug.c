/* debug.c
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

#include "debug.h"
#include "xalloc.h"

static int do_debug(struct abstract_write **w,
		    struct lsh_string *packet)
{
  struct packet_debug *closure
    = (struct packet_debug *) *w;
  
  UINT32 i;
  
  fprintf(closure->output, "DEBUG: (packet size %d = 0x%x)\n",
	  packet->length, packet->length);

  for(i=0; i<packet->length; i++)
  {
    if (! i%16)
      fprintf(closure->output, "\n%08x: ", i);
    
    fprintf(closure->output, "%02x ", packet->data[i]);
  }

  fprintf(closure->output, "\n");

  return A_WRITE(closure->super.next, packet);
}

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, FILE *output)
{
  struct packet_debug *closure = xalloc(sizeof(struct packet_debug));

  closure->super.super.write = do_debug;
  closure->super.next = continuation;
  closure->output = output;

  return &closure->super.super;
}


