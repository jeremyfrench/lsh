/* interact.h
 *
 * Interact with the user.
 *
 * $Id$*/

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Niels Möller
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

#ifndef LSH_INTERACT_H_INCLUDED
#define LSH_INTERACT_H_INCLUDED

#include "lsh.h"

/* Abstract class defining methods needed to comminucate with the
   user's terminal. */

struct terminal_dimensions
{
  UINT32 char_width;
  UINT32 char_height;
  UINT32 pixel_width;
  UINT32 pixel_heght;
};

/* GABA:
   (class
     (name abstract_interact)
     (vars
       (is_tty method int)
       ; (read_line method int "UINT32 size" "UINT8 *buffer")
       (read_password method string
                  "UINT32 max_length"
                  "struct lsh_string *prompt"
		  "int free")
       (yes_or_no method int
                  "struct lsh_string *prompt"
		  "int def" "int free")
       (window_change method int
                  "struct terminal_dimensions *d")))
*/

extern int tty_fd;

int lsh_open_tty(void);
int tty_read_line(UINT32 size, UINT8 *buffer);
int yes_or_no(struct lsh_string *s, int def, int free);

#endif /* LSH_INTERACT_H_INCLUDED */
