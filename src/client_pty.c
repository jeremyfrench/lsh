/* client_pty.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, Niels Möller, Balázs Scheidler
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

#include "client_pty.h"

#include "channel_commands.h"
#include "format.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "client_pty.c.x"

/* GABA:
   (class
     (name pty_request)
     (super channel_request_command)
     (vars
       (tty . int)
       (term string)
       (ios . "struct termios")
       (width . UINT32)
       (height . UINT32)
       (width_p . UINT32)
       (height_p . UINT32)))
*/

/* FIXME: Add a resource, to make sure that the tty is reset and
 * closed when the channel dies. */

/* GABA:
   (class
     (name pty_request_continuation)
     (super command_frame)
     (vars
       (req object pty_request)))
*/

/* FIXME: !!! failed requests show up as an exception. /Bazsi
 *
 * I think that is normal. It's up to the caller to do something reasonable
 * about the exception. /nisse
 */
static void
do_pty_continuation(struct command_continuation *s,
		    struct lsh_object *x)
{
  CAST(pty_request_continuation, self, s);

  assert(x);
  verbose("lsh: pty request succeeded\n");
  
  CFMAKERAW(&self->req->ios);
  if (!tty_setattr(self->req->tty, &self->req->ios))
    {
      werror("do_pty_continuation: "
	     "Setting the attributes of the local terminal failed.\n");
    }

  COMMAND_RETURN(self->super.up, x);
}

static struct command_continuation *
make_pty_continuation(struct pty_request *req,
		      struct command_continuation *c)
{
  NEW(pty_request_continuation, self);
  self->req = req;
  self->super.up = c;
  self->super.super.c = do_pty_continuation;
  
  return &self->super.super;
}

static struct lsh_string *
do_format_pty_request(struct channel_request_command *s,
		      struct ssh_channel *channel,
		      struct command_continuation **c)
{
  CAST(pty_request, self, s);

  verbose("lsh: Requesting a remote pty.\n");

  *c = make_pty_continuation(self, *c);

  return format_channel_request(ATOM_PTY_REQ, channel, 1,
				"%S%i%i%i%i%S",
				self->term,
				self->width, self->height,
				self->width_p, self->height_p,
				tty_encode_term_mode(&self->ios));
}

struct command *make_pty_request(int tty)
{
  NEW(pty_request, req);
  char *term = getenv("TERM");

  if (!tty_getattr(tty, &req->ios))
    {
      KILL(req);
      return NULL;
    }
  
  if (!tty_getwinsize(tty, &req->width, &req->height,
		      &req->width_p, &req->height_p))
    req->width = req->height = req->width_p = req->height_p = 0;

  req->super.format_request = do_format_pty_request;
  req->super.super.call = do_channel_request_command;
  
  req->tty = tty;
  req->term = term ? format_cstring(term) : ssh_format("");

  return &req->super.super;
}
