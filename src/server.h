/* server.h
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

#ifndef LSH_SERVER_H_INCLUDED
#define LSH_SERVER_H_INCLUDED

#include "io.h"
#include "keyexchange.h"
#include "ssh1_fallback.h"

#if 0
struct fd_listen_callback *
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
#endif

struct command *make_offer_service(struct alist *services);

#endif /* LSH_SERVER_H_INCLUDED */
