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

#define GABA_DECLARE
#include "tcpforward.h.x"
#undef GABA_DECLARE

/* this class encapsulates tcpip_forward global requests currently
 * opened by the client. */

/* GABA:
   (class
     (name forwarded_tcpip)
     ; (inherit resource)
     (vars
       (next object forwarded_tcpip)
       (bind_host string)
       (bind_port simple UINT32)
       (listen object listen_fd)))
*/

struct channel_open *make_open_direct_tcpip(struct io_backend *backend);

struct global_request *make_tcpip_forward_request(struct io_backend *backend);

struct global_request *make_cancel_tcpip_forward_request(void);

#endif
