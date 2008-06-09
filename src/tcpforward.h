
/* tcpforward.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balázs Scheidler, Niels Möller
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

#ifndef LSH_TCPFORWARD_H_INCLUDED
#define LSH_TCPFORWARD_H_INCLUDED

#include "channel.h"
#include "io.h"
#include "resource.h"
#include "xalloc.h"

#define GABA_DECLARE
#include "tcpforward.h.x"
#undef GABA_DECLARE

#define TCPIP_WINDOW_SIZE 10000

struct command *
forward_local_port(const struct address_info *local,
		   const struct address_info *target);

struct command *
forward_remote_port(const struct address_info *port,
		    const struct address_info *target);

/* GABA:
   (class
     (name forwarded_port)
     (vars
       ; The key we use for looking up the port
       (address const object address_info)))
*/

struct forwarded_port *
tcpforward_lookup(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port);

struct forwarded_port *
tcpforward_remove(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port);

int
tcpforward_remove_port(struct object_queue *q, struct forwarded_port *port);

struct resource *
tcpforward_connect(const struct address_info *a,
		   const struct channel_open_info *info);

struct io_listen_port *
make_tcpforward_listen_port(struct ssh_connection *connection,
			    int type,
			    const struct address_info *local,
			    const struct address_info *forward);


extern struct channel_open channel_open_direct_tcpip;
extern struct channel_open channel_open_forwarded_tcpip;

extern struct global_request
tcpip_forward_handler;

extern struct global_request
tcpip_cancel_forward_handler;

struct command *
make_socks_server(const struct address_info *local);

#endif /* LSH_TCPFORWARD_H_INCLUDED */
