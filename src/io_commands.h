/* io_commands.h
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

#ifndef LSH_IO_COMMANDS_H_INCLUDED
#define LSH_IO_COMMANDS_H_INCLUDED

#include "command.h"
#include "connection.h"
#include "io.h"

#define GABA_DECLARE
#include "io_commands.h.x"
#undef GABA_DECLARE

/* Returned by listen */
/* GABA:
   (class
     (name listen_value)
     (vars
       (fd object io_fd)
       (peer object address_info)))
*/

struct command *make_listen_command(struct command *callback,
				    struct io_backend *backend);

extern struct collect_info_1 listen_command;

struct command *make_simple_connect(struct io_backend *backend,
				    struct resource_list *resources);
struct command *
make_simple_listen(struct io_backend *backend,
		   struct resource_list *resources);

extern struct command_simple io_log_peer_command;

#endif /* LSH_IO_COMMANDS_H_INCLUDED */
