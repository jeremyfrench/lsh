/* zlib.h
 *
 * Processor to compress packets using zlib
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

#ifndef LSH_ZLIB_H_INCLUDED
#define LSH_ZLIB_H_INCLUDED

/* The input to the compressor should be a packet with payload only. */
struct zlib_processor
{
  struct abstract_write_pipe c;
  z_stream state;
}

struct packet_processor *make_zlib_processor(packet_processor *continuation,
					     level);

#endif /* LSH_ZLIB_H_INCLUDED */
