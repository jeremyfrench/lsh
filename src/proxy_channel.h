/* proxy_channel.h
 *
 * $Id$ */

#warning proxy_channel.h is obsolete; replaced by gateway_channel.h

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2000 Balázs Scheidler
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

#ifndef LSH_PROXY_CHANNEL_H_INCLUDED
#define LSH_PROXY_CHANNEL_H_INCLUDED

#include "channel.h"

#define GABA_DECLARE
#include "proxy_channel.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name proxy_channel)
     (super ssh_channel)
     (vars
       (chain object proxy_channel)
       (init_io method void)))
*/

#define PROXY_CHANNEL_INIT_IO(c) ((c)->init_io(c))

struct proxy_channel *
make_proxy_channel(UINT32 window_size,
		   UINT32 rec_max_packet,
		   struct alist *request_types,
		   int client_side);

struct command *
make_proxy_channel_open_command(UINT32 type,
				UINT32 max_packet,
                                struct lsh_string *open_request,
				struct alist *requests);

struct command_continuation *
make_proxy_channel_open_continuation(struct command_continuation *up,
				     struct proxy_channel *channel);

extern struct global_request proxy_global_request;
extern struct channel_request proxy_channel_request;
		   
#endif
