/* command.h
 *
 * $id$ */

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

#ifndef LSH_COMMAND_H_INCLUDED
#define LSH_COMMAND_H_INCLUDED

#include "lsh_object.h"

#include "command.h.x"

/* Continuation based command execution. A command can take one object
 * as argument, and returns one object. */

/* CLASS
   (class
     (name command_continuation)
     (vars
       (c method int "struct lsh_object *result")))
*/

/* CLASS:
   (class
     (name command)
     (vars
       (do method int "struct command_continuation *c"
                      "struct lsh_object *arg")))
*/

#define COMMAND_DO(f, c) ((f)->do((f), (c)))
#define COMMAND_RETURN(c, v) ((c)->c((c), (struct lsh_object *) (v)))

#endif /* LSH_COMMAND_H_INCLUDED */ 
