/* debug.h
 *
 * Packet processor dumping packets to a file.
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

#ifndef LSH_DEBUG_H_INCLUDED
#define LSH_DEBUG_H_INCLUDED

#include <stdio.h>
#include "abstract_io.h"

struct packet_debug
{
  struct abstract_write_pipe super;
  FILE *output;
};

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, FILE *output);


#endif */ LSH_DEBUG_H_INCLUDED */
