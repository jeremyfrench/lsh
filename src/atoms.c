/* atoms.c
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

#include "atoms.h"

#include "atoms_gperf.c"

struct atom_rassoc
{
  UINT8 *name;
  UINT32 length;
};

struct atom_rassoc atom_table[] =
#include "atoms_table.c"
;

UINT32 get_atom_length(int atom)
{ return atom_table[atom].length; }

UINT8 *get_atom_name(int atom)
{ return atom_table[atom].name; }
  
UINT32 lookup_atom(UINT32 length, UINT8 *name)
{
  struct atom_assoc *pair = gperf_atom(name, length);

  return pair ? pair->id : 0;
}


