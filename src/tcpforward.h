/* tcpforward.h
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balazs Scheidler, Niels Möller
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

#if 0
#define GABA_DECLARE
#include "tcpforward.h.x"
#undef GABA_DECLARE
#endif

struct ssh_channel *make_tcpip_channel(struct io_fd *socket);

struct channel_open *make_channel_open_direct_tcpip(struct io_backend *backend);
struct channel_open channel_open_forwarded_tcpip;

struct global_request *make_tcpip_forward_request(struct io_backend *backend);

struct global_request *make_cancel_tcpip_forward_request(void);

struct command *forward_local_port(struct io_backend *backend,
				   struct address_info *local,
				   struct address_info *target);

struct command *forward_remote_port(struct io_backend *backend,
				    struct address_info *local,
				    struct address_info *target);

#endif /* LSH_TCPFORWARD_H_INCLUDED */
