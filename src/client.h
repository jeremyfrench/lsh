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
#include "abstract_crypto.h"

struct client_callback
{
  struct fd_callback super;
  struct io_backend *backend;
  UINT32 block_size;
  char *id_comment;
  struct randomness *random;
};

struct fd_callback *make_client_callback(struct io_backend *b,
					 char *comment,
					 UINT32 block_size,
					 struct randomness *r);

#if 0
struct client_session
{
  struct read_handler handler;
  UINT32 *
#endif
  
#endif /* LSH_CLIENT_H_INCLUDED */
