/* server_pty.h
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, Niels Möller, Balazs Scheidler
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

#ifndef LSH_SERVER_PTY_H_INCLUDED
#define LSH_SERVER_PTY_H_INCLUDED

#include "lsh.h"

#include "resource.h"
#include <termios.h>

#define MAX_TTY_NAME	32

#define CLASS_DECLARE
#include "server_pty.h.x"
#undef CLASS_DECLARE


/* CLASS:
   (class 
     (name pty_info)
     (super resource)
       (vars
         (master simple int)
	 (slave simple int)
	 ; FIXME: Is this used for anything?
	 ;; (tty_name array (simple char) MAX_TTY_NAME)
	 ;; (saved_ios simple "struct termios")
	 ));
*/

struct pty_info *make_pty_info(void);
int pty_allocate(struct pty_info *pty);
void tty_interpret_term_modes(struct termios *ios, UINT32 t_len, UINT8 *t_modes);

#endif /* LSH_SERVER_PTY_H_INCLUDED */
