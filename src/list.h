/* list.h
 *
 * Variable length lists of atoms (or other integers).
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

#ifndef LSH_LIST_H_INCLUDED
#define LSH_LIST_H_INCLUDED

#include "lsh_types.h"

#define CLASS_DECLARE
#include "list.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name lsh_list)
     (vars
       (length simple unsigned)
       ; This is really of variable size
       (elements array int 1)))
*/

#define LIST(x) ((x)->elements)
struct lsh_list *make_list(unsigned length, ...);

#endif /* LSH_LIST_H_INCLUDED */
