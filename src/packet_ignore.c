/* packet_ignore.c
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

#include "packet_ignore.h"

#include "xalloc.h"

static int do_ignore(struct packet_handler *closure,
		     struct ssh_connection *connection,
		     struct lsh_string *packet)
{
  lsh_string_free(packet);
  return LSH_OK | LSH_GOON;
}

struct packet_handler *make_ignore_handler(void)
{
  NEW(packet_handler, res);

  res->handler = do_ignore;
  return res;
}

