/* service.h
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_SERVICE_H_INCLUDED
#define LSH_SERVICE_H_INCLUDED

#include "alist.h"
#include "connection.h"

/* Used on both client and server side */

/* The init function only returns 1 on success, 0 on failure. */
struct ssh_service
{
  int (*init)(struct ssh_service *self, struct ssh_connection *c);
};

#define SERVICE_INIT(s, c) ((s)->init((s), (c)))

/* services is an alist mapping names to service objects */
struct packet_handler *make_service_handler(struct alist *services); 

struct lsh_string *format_service_request(int name);

int request_service(int name, struct ssh_service * service);

struct lsh_string *format_service_accept(int name);

struct ssh_service *make_meta_service(struct alist *services);

#endif /* LSH_SERVICE_H_INCLUDED */
