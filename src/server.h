/* server.h
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_SERVER_H_INCLUDED
#define LSH_SERVER_H_INCLUDED

#include "io.h"
#include "keyexchange.h"
#include "password.h"
#include "reaper.h"

#if SSH1_FALLBACK
#include ssh1_fallback.h
#else /* !SSH1_FALLBACK */
struct ssh1_fallback;
#endif /* !SSH1_FALLBACK */

struct fd_callback *
make_server_callback(struct io_backend *b,
		     const char *comment,
		     /* NULL if no falling back should be attempted. */
		     struct ssh1_fallback *fallback,
		     UINT32 block_size,
		     struct randomness *random,		     
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler);

struct read_handler *make_server_read_line(struct ssh_connection *c,
					   int fd,
					   struct ssh1_fallback *fallback);
struct close_callback *make_server_close_handler(struct ssh_connection *c);

struct ssh_channel *make_server_session(struct unix_user *user,
					UINT32 max_window,
					struct alist *request_types);

struct unix_service *make_server_session_service(struct alist *global_requests,
						 struct alist *session_requests);

struct channel_open *make_open_session(struct unix_user *user,
				       struct alist *session_requests);

struct channel_request *make_shell_handler(struct io_backend *backend,
					   struct reap *reap);

struct lsh_string *format_exit_signal(struct ssh_channel *channel,
				      int core, int signal);
struct lsh_string *format_exit(struct ssh_channel *channel, int value);

struct resource *make_process_resource(pid_t pid, int signal);

#endif /* LSH_SERVER_H_INCLUDED */
