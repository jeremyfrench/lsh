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

#include "channel.h"
#include "command.h"
#include "resource.h"

#define GABA_DECLARE
#include "server_x11.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name server_x11_info)
     (vars
       (display string)
       (xauthority string)))
*/

struct server_x11_info *
server_x11_setup(struct ssh_channel *channel, struct lsh_user *user,
		 const struct lsh_string *protocol,
		 const struct lsh_string *cookie,
		 UINT32 screen);

#if 0
/* Returns the display */
const struct lsh_string *
server_x11_setup(struct ssh_channel *channel, struct lsh_user *user,
		 UINT32 protocol_length, const UINT8 *protocol,
		 UINT32 cookie_length, const UINT8 *cookie);

/* ;; GABA:
   (class
     (name server_x11_info)
     (super resource)
     (vars
       (display string)
       (socket object lsh_fd)
       ;; Filename of xauth file
       (xauth string)))
*/

struct server_x11_info *
make_server_x11_info(UINT32 protocol_length, const UINT8 *protocol,
		     UINT32 cookie_length, const UINT8 *cookie,
		     struct lsh_user *user)
{
}

/* Start listening on an AF_UNIX socket, and run xauth */
void
server_x11_listen(struct server_x11_info *info,
		  struct ssh_connection *connection,
		  struct command_continuation *c,
		  struct exception_handler *e);
#endif
#endif /* LSH_SERVER_X11_H_INCLUDED */
