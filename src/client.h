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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_CLIENT_H_INCLUDED
#define LSH_CLIENT_H_INCLUDED

#include "io.h"
#include "keyexchange.h"

struct fd_callback *
make_client_callback(struct io_backend *b,
		     char *comment,
		     UINT32 block_size,
		     struct randomness *random,
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler);

struct read_handler *make_client_read_line(struct ssh_connection *c);
struct close_callback *make_client_close_handler(void);

struct packet_handler *make_accept_service_handler(int service_name,
						   struct ssh_service *service);

struct ssh_service *request_service(int service_name,
				    struct ssh_service *service);

struct connection_startup *make_client_startup(struct io_fd *in,
					       struct abstract_write *out,
					       struct abstract_write *err,
					       int final_request,
					       struct lsh_string *args);

#endif /* LSH_CLIENT_H_INCLUDED */
