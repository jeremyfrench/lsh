/* client_pty.c
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

#include "client_pty.h"

struct lsh_string *
format_pty_req(struct ssh_channel *channel, int want_reply, 
	       UINT8 *term, UINT32 width, UINT32 height, UINT32 width_p, 
	       UINT32 height_p, struct lsh_string *term_modes)
{
  return format_channel_request(ATOM_PTY_REQ, channel, want_reply, 
				"%s%i%i%i%i%S",
				strlen(term),
				term,
				width, height,
				width_p, height_p,
				term_modes);
}


