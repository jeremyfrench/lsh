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

/* GABA:
   (class
     (name io_write_file_info)
     (vars
       (name string)
       (flags . int)
       (mode . int)
       (block_size . UINT32)))
*/

struct io_write_file_info *
make_io_write_file_info(struct lsh_string *name, int flags, int mode, UINT32 block_size);

extern struct command io_write_file_command;

#define IO_WRITE_FILE (&io_write_file_command.super)


struct command *
make_listen_with_callback(struct command *callback);

extern struct command_2 listen_with_callback;
#define LISTEN_CALLBACK (&listen_with_callback.super.super)

struct command *
make_connect_port(struct address_info *target);

extern struct command_2 connect_connection_command;
#define CONNECT_CONNECTION (&connect_connection_command.super.super)

extern struct command connect_simple_command;
#define CONNECT_SIMPLE (&connect_simple_command.super)

struct command *
make_listen_local(struct local_info *info);

struct command *
make_connect_local(void);

extern struct command connect_local_command;
#define CONNECT_LOCAL (&connect_local_command.super)

extern struct command io_log_peer_command;
#define LOG_PEER (&io_log_peer_command.super)

#endif /* LSH_IO_COMMANDS_H_INCLUDED */
