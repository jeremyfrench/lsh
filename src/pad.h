/* pad.h
 *
 * Processor for padding and formatting ssh-packets
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

#ifndef LSH_PAD_H_INCLUDED
#define LSH_PAD_H_INCLUDED

#include "abstract_io.h"
#include "abstract_crypto.h"

/* Input to the processor is a packet with the payload. Output is a
 * packet containing a formatted ssh packet (with correct byte order,
 * etc). */
struct packet_pad
{
  struct abstract_write_pipe super;

  unsigned block_size; /* At least 8, even for stream ciphers */

  struct randomness *random;
  void *state;
};

struct abstract_write *
make_packet_pad(struct abstract_write *continuation,
		unsigned block_size,
		struct randomness *random);

#endif /* LSH_PAD_H_INCLUDED */
