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

  channel_send_request(self->channel, ATOM_WINDOW_CHANGE, 0,
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
     (name client_pty_action)
     (super client_session_action)
     (vars
       (tty object interact)
       (attr object terminal_attributes)))
*/

static void
do_action_pty_start(struct client_session_action *s,
		    struct client_session *session)
{
  CAST(client_pty_action, self, s);

  struct terminal_dimensions dims;
  char *term;
  
  trace("do_action_pty_start: Sending pty request.\n");

  if (!INTERACT_WINDOW_SIZE(self->tty, &dims))
    dims.char_width = dims.char_height
      = dims.pixel_width = dims.pixel_height = 0;

  self->attr = INTERACT_GET_ATTRIBUTES(self->tty);
  term = getenv(ENV_TERM);

  channel_send_request(&session->super, ATOM_PTY_REQ, 1,
		       "%z%i%i%i%i%fS",
		       term ? term : "",
		       dims.char_width, dims.char_height,
		       dims.pixel_width, dims.pixel_height,
		       TERM_ENCODE(self->attr));
}

static void
do_action_pty_success(struct client_session_action *s,
		      struct client_session *session)
{
  CAST(client_pty_action, self, s);

  struct terminal_attributes *raw;
  
  verbose("pty request succeeded\n");
  
  raw = TERM_MAKE_RAW(self->attr);
  if (!INTERACT_SET_ATTRIBUTES(self->tty, raw))
    {
      werror("action_pty_success: "
	     "Setting the attributes of the local terminal failed.\n");
    }

  /* Tell the werror functions that terminal mode is restored. */
  set_error_raw(1);
  
  remember_resource(session->resources,
		    make_client_tty_resource(self->tty, self->attr));
  
  remember_resource(session->resources,
		    INTERACT_WINDOW_SUBSCRIBE
		    (self->tty, make_client_winch_handler(&session->super)));
}

static int
do_action_pty_failure(struct client_session_action *s UNUSED,
		      struct client_session *session UNUSED)
{
  verbose("pty request failed\n");

  return 1;
}

struct client_session_action *
make_pty_action(struct interact *tty)
{
  NEW(client_pty_action, self);
  self->super.serial = 0;
  self->super.start = do_action_pty_start;
  self->super.success = do_action_pty_success;
  self->super.failure = do_action_pty_failure;

  self->tty = tty;
  self->attr = NULL;

  return &self->super;
}
