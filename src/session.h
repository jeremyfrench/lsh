/* session.h
 *
 * Manage the ssh-connection service.
 *
 * $Id$
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

#ifndef LSH_SESSION_H_INCLUDED
#define LSH_SESSION_H_INCLUDED

#warning session.h should not be used (yet?).

#include "alist.h"
#include "connection.h"
#include "channel.h"
#include "parse.h"

struct ssh_session
{
  struct channel super;

  
};

struct lsh_string *format_session_open(UINT32 channel,
				       UINT32 window_size, UINT32 max_packet);

				       
#endif /* LSH_SESSION_H_INCLUDED */
