/* connection_commands.h
 *
 * $Id$
 */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef LSH_CONNECTION_COMMANDS_H_INCLUDED
#define LSH_CONNECTION_COMMANDS_H_INCLUDED

#include "alist.h"
#include "command.h"
#include "connection.h"
#include "keyexchange.h"
#include "ssh1_fallback.h"

struct close_callback *make_connection_close_handler(struct ssh_connection *c);

struct command *
make_handshake_command(int mode,
		       const char *id,
		       UINT32 block_size,
		       struct randomness *r,
		       struct alist *algorithms,
		       struct make_kexinit *init,
		       struct ssh1_fallback *fallback);

extern struct collect_info_1 connection_remember_command;

#define CONNECTION_REMEMBER (&connection_remember_command.super)

#endif /* LSH_CONNECTION_COMMANDS_H_INCLUDED */
