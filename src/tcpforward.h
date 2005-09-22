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

struct command *
tcpforward_direct_tcpip(struct address_info *local,
			struct address_info *target);

/* GABA:
   (class
     (name forwarded_port)
     (vars
       ; The key we use for looking up the port
       (address object address_info)))
*/

struct forwarded_port *
tcpforward_lookup(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port);

int
tcpforward_remove_port(struct object_queue *q, struct forwarded_port *port);


/* Used by the client to keep track of remotely forwarded ports */
/* GABA:
   (class
     (name remote_port)
     (super forwarded_port)
     (vars
       ; Invoked when a forwarded_tcpip request is received.
       ; Called with the struct address_info *peer as argument.
       (callback object command)))
*/

#if 0
struct remote_port *
make_remote_port(struct address_info *listen,
		 struct command *callback);

struct channel_open *
make_channel_open_direct_tcpip(struct command *callback);

extern struct channel_open channel_open_forwarded_tcpip;

struct global_request *
make_tcpip_forward_request(struct command *callback);
#endif

extern struct global_request
tcpip_forward_handler;

extern struct global_request
tcpip_cancel_forward_handler;

#if 0
struct command *
make_open_tcpip_command(int type,
			struct address_info *port,
			struct listen_value *peer);

struct command *
make_forward_local_port(struct address_info *local,
			struct address_info *target);

struct command *
make_forward_remote_port(struct address_info *local,
			 struct address_info *target);

struct command *
make_direct_tcpip_hook(void);

struct command *
make_tcpip_forward_hook(void);

struct command *
make_socks_server(struct address_info *local);

#endif
#endif /* LSH_TCPFORWARD_H_INCLUDED */
