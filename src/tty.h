/* tty.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2008, Niels Möller, Balázs Scheidler
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

#ifndef LSH_TTY_H_INCLUDED
#define LSH_TTY_H_INCLUDED

#include <termios.h>

#include "lsh.h"

struct lsh_string *
tty_encode_term_mode(const struct termios *ios);

int
tty_decode_term_mode(struct termios *ios, uint32_t t_len, const uint8_t *t_modes);

#endif /* LSH_TTY_H_INCLUDED */
