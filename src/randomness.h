/* randomness.h
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

#ifndef LSH_RANDOMNESS_H_INCLUDED
#define LSH_RANDOMNESS_H_INCLUDED

#include "abstract_crypto.h"

#define CLASS_DECLARE
#include "randomness.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name randomness)
     (vars
       (quality . int)
       (random method void "UINT32 length" "UINT8 *dst")))
*/

#define RANDOM(r, length, dst) ((r)->random((r), length, dst))

/* Consumes the init string (which may be NULL). */
struct randomness *make_poor_random(struct hash_algorithm *hash,
				    struct lsh_string *init);

struct randomness *make_device_random(const char *device);
struct randomness *make_reasonably_random(void);

#endif /* LSH_RANDOMNESS_H_INCLUDED */
