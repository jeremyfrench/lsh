/* server_x11.h
 *
 * $id:$
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2002 Niels Möller
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

#ifndef LSH_SERVER_X11_H_INCLUDED
#define LSH_SERVER_X11_H_INCLUDED

#include "command.h"

struct server_x11_info;

struct server_x11_info *
make_server_x11_info(UINT32 protocol_length, const UINT8 *protocol,
		     UINT32 cookie_length, const UINT8 *cookie,
		     struct lsh_user *user);

/* Start listening on an AF_UNIX socket, and run xauth */
void
server_x11_listen(struct server_x11_info *info,
		  struct ssh_connection *connection,
		  struct command_continuation *c,
		  struct exception_handler *e);

#endif /* LSH_SERVER_X11_H_INCLUDED */
