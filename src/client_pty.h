/* client_pty.h
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

#ifndef LSH_CLIENT_PTY_H_INCLUDED
#define LSH_CLIENT_PTY_H_INCLUDED

#include "lsh.h"
#include "command.h"

struct command *make_pty_request(int tty);

#if 0
struct lsh_string *
format_pty_req(struct ssh_channel *channel, int want_reply, 
	       UINT8 *term, UINT32 width, UINT32 height, UINT32 width_p, 
	       UINT32 height_p, struct lsh_string *term_modes);
#endif

#endif /* LSH_CLIENT_PTY_H_INCLUDED */

