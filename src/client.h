/* client.h
 *
 *
 *
 * $Id$ */

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

#ifndef LSH_CLIENT_H_INCLUDED
#define LSH_CLIENT_H_INCLUDED

#include "channel_commands.h"
#include "io.h"
#include "keyexchange.h"

struct request_info;

struct fd_callback *
make_client_callback(struct io_backend *b,
		     const char *comment,
		     UINT32 block_size,
		     struct randomness *random,
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler);

struct read_handler *make_client_read_line(struct ssh_connection *c);
struct close_callback *make_client_close_handler(void);

struct packet_handler *
make_accept_service_handler(int service,
			    struct command_continuation *c,
			    struct exception_handler *e);

struct command *make_request_service(int service);

struct channel_request *make_handle_exit_status(int *exit_code);
struct channel_request *make_handle_exit_signal(int *exit_code);

struct command *make_open_session_command(struct ssh_channel *session);


extern struct channel_request_command request_shell;
extern struct command client_io;

struct ssh_channel *make_client_session(struct io_fd *in,
					struct io_fd *out,
					struct io_fd *err,
					UINT32 max_window,
					int *exit_status);

     
#endif /* LSH_CLIENT_H_INCLUDED */
