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

#include "server.h"

#include "io.h"
#include "keyexchange.h"

struct server_callback
{
  struct fd_callback super;
  struct io_backend *backend;

  struct signer *secret;        /* secret key */
  struct lsh_string *host_key;  /* public key */
  UINT32 block_size;
  char *id_comment;

  struct randomness *random;
  struct make_kexinit *init;
  struct packet_handler *kexinit_handler;
};

struct fd_callback *
make_server_callback(struct io_backend *b,
		     char *comment,
		     UINT32 block_size,
		     struct randomness *random,		     
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler);

struct read_handler *make_server_read_line(struct ssh_connection *c);
struct callback *make_server_close_handler(void);

#endif /* LSH_SERVER_H_INCLUDED */
