/* tcpforward_commands.h
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

#include "tcpforward.h"

#if 0
#define GABA_DECLARE
#include "tcpforward_commands.h.x"
#endif GABA_DECLARE

/* ;;GABA:
   (class
     (name remote_listen_value)
     (vars
       (c object channel_open_callback)
       (peer object address_info)))
*/

static struct remote_listen_value *
make_remote_listen_value(struct channel_open_callback *c,
			 struct address_info *peer)
{
  NEW(remote_listen_value, res);
  res->c = c;
  res->peer = peer;

  return res;
}
#endif

#endif /* LSH_TCPFORWARD_H_INCLUDED */
