/* proxy_session.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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

#include "proxy_session.h"
#include "xalloc.h"
#include "ssh.h"
#include "werror.h"

#include "proxy_session.c.x"

#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

/* GABA:
   (class
     (name proxy_channel)
     (super ssh_channel)
     (vars
       (chain object proxy_channel)))
*/

static struct ssh_channel *
make_proxy_channel(UINT32 window_size,
		   struct alist *session_requests)
{
  return NULL;
}

/* GABA:
   (class
     (name proxy_open_session)
     (super channel_open)
     (vars
       (session_requests object alist)))
*/

static void
do_proxy_open_session(struct channel_open *s,
		      struct ssh_connection *connection,
		      struct simple_buffer *args,
		      struct command_continuation *c,
		      struct exception_handler *e)
{
  CAST(proxy_open_session, closure, s);

  debug("server.c: do_proxy_open_session()\n");

  if (parse_eod(args))
    {
      
    }
  else
    {
      PROTOCOL_ERROR(e, "trailing garbage in open message");
    }
}

struct channel_open *
make_proxy_open_session(struct alist *session_requests)
{
  NEW(proxy_open_session, self);

  self->super.handler = do_proxy_open_session;
  self->session_requests = session_requests;
  return &self->super;
}
