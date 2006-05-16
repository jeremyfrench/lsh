/* client_pty.c
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "client.h"

#include "environ.h"
#include "format.h"
#include "interact.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include "client_pty.c.x"

/* GABA:
   (class
     (name pty_request)
     (super command)
     (vars
       (tty object interact)
       (term string)
       (attr object terminal_attributes)
       (dims . "struct terminal_dimensions")))
*/

/* GABA:
   (class
     (name client_tty_resource)
     (super resource)
     (vars
       (tty object interact)
       (attr object terminal_attributes)))
*/

static void
do_kill_client_tty_resource(struct resource *s)
{
  CAST(client_tty_resource, self, s);
  self->super.alive = 0;
  INTERACT_SET_ATTRIBUTES(self->tty, self->attr);
  /* Tell the werror functions that terminal mode is restored. */
  set_error_raw(0);
}

static struct resource *
make_client_tty_resource(struct interact *tty,
			 struct terminal_attributes *attr)
{
  NEW(client_tty_resource, self);
  init_resource(&self->super, do_kill_client_tty_resource);

  self->tty = tty;
  self->attr = attr;

  return &self->super;
}

/* GABA:
   (class
     (name client_winch_handler)
     (super window_change_callback)
     (vars
       (channel object ssh_channel)))
*/

static void
do_client_winch_handler(struct window_change_callback *s,
			struct interact *tty)
{
  CAST(client_winch_handler, self, s);
  struct terminal_dimensions dims;

  if (!INTERACT_WINDOW_SIZE(tty, &dims))
    return;

  channel_send_request(self->channel, ATOM_WINDOW_CHANGE,
		       0, NULL,
		       "%i%i%i%i",
		       dims.char_width, dims.char_height,
		       dims.pixel_width, dims.pixel_height);
}

static struct window_change_callback *
make_client_winch_handler(struct ssh_channel *channel)
{
  NEW(client_winch_handler, self);
  self->super.f = do_client_winch_handler;
  self->channel = channel;

  return &self->super;
}

       
/* GABA:
   (class
     (name pty_request_continuation)
     (super command_frame)
     (vars
       (req object pty_request)))
*/

/* NOTE: Failed requests show up as exceptions. */
static void
do_pty_continuation(struct command_continuation *s,
		    struct lsh_object *x)
{
  CAST(pty_request_continuation, self, s);
  CAST(client_session, session, x);
  struct terminal_attributes *raw;
  
  assert(x);
  verbose("pty request succeeded\n");
  
  raw = TERM_MAKE_RAW(self->req->attr);
  if (!INTERACT_SET_ATTRIBUTES(self->req->tty, raw))
    {
      werror("do_pty_continuation: "
	     "Setting the attributes of the local terminal failed.\n");
    }

  /* Tell the werror functions that terminal mode is restored. */
  set_error_raw(1);
  
  remember_resource(session->resources,
		    make_client_tty_resource(self->req->tty,
					     self->req->attr));
  
  remember_resource(session->resources,
		    INTERACT_WINDOW_SUBSCRIBE
		    (self->req->tty,
		     make_client_winch_handler(&session->super)));
  
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

static void
do_pty_request(struct command *s,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(pty_request, self, s);
  CAST_SUBTYPE(ssh_channel, channel, x);

  struct command_context *ctx
    = make_command_context(make_pty_continuation(self, c), e);

  trace("do_pty_request: Sending pty request.\n");

  channel_send_request(channel, ATOM_PTY_REQ,
		       1, ctx,
		       "%S%i%i%i%i%fS",
		       self->term,
		       self->dims.char_width, self->dims.char_height,
		       self->dims.pixel_width, self->dims.pixel_height,
		       TERM_ENCODE(self->attr));
}

struct command *
make_pty_request(struct interact *tty)
{
  NEW(pty_request, req);
  char *term = getenv(ENV_TERM);

  req->super.call = do_pty_request;
  
  req->attr = INTERACT_GET_ATTRIBUTES(tty);

  if (!req->attr)
    {
      KILL(req);
      return NULL;
    }
  
  if (!INTERACT_WINDOW_SIZE(tty, &req->dims))
    req->dims.char_width = req->dims.char_height
      = req->dims.pixel_width = req->dims.pixel_height = 0;
  
  req->tty = tty;
  req->term = term ? make_string(term) : ssh_format("");

  return &req->super;
}
