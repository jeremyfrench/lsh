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

static void
do_kill_client_tty_resource(struct resource *self)
{
  trace("do_kill_client_tty_resource\n");

  if (self->alive)
    {
      self->alive = 0;
      interact_set_mode(0);
      /* Tell the werror functions that terminal mode is restored. */
      set_error_raw(0);
    }
}

static struct resource *
make_client_tty_resource(void)
{
  NEW(resource, self);
  init_resource(self, do_kill_client_tty_resource);

  return self;
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
			const struct winsize *dims)
{
  CAST(client_winch_handler, self, s);

  channel_send_request(self->channel, ATOM_WINDOW_CHANGE, 0,
		       "%i%i%i%i",
		       dims->ws_col, dims->ws_row,
		       dims->ws_xpixel, dims->ws_ypixel);
}

static struct window_change_callback *
make_client_winch_handler(struct ssh_channel *channel)
{
  NEW(client_winch_handler, self);
  self->super.f = do_client_winch_handler;
  self->channel = channel;

  return &self->super;
}


static void
do_action_pty_start(struct client_session_action *s UNUSED,
		    struct client_session *session)
{
  struct winsize dims;
  char *term;
  
  trace("do_action_pty_start: Sending pty request.\n");

  if (!interact_get_window_size(&dims))
    dims.ws_col = dims.ws_row
      = dims.ws_xpixel = dims.ws_ypixel = 0;

  term = getenv(ENV_TERM);

  channel_send_request(&session->super, ATOM_PTY_REQ, 1,
		       "%z%i%i%i%i%fS",
		       term ? term : "",
		       dims.ws_col, dims.ws_row,
		       dims.ws_xpixel, dims.ws_ypixel,
		       tty_encode_term_mode(interact_get_terminal_mode()));
}

static void
do_action_pty_success(struct client_session_action *s UNUSED,
		      struct client_session *session)
{
  verbose("pty request succeeded\n");

  if (!interact_set_mode(1))
    {
      werror("action_pty_success: "
	     "Setting the attributes of the local terminal failed.\n");
    }

  /* Tell the werror functions that terminal mode is raw. */
  set_error_raw(1);
  
  remember_resource(session->resources, make_client_tty_resource());
  
  remember_resource(session->resources,
		    interact_on_window_change(make_client_winch_handler(&session->super)));
}

static int
do_action_pty_failure(struct client_session_action *s UNUSED,
		      struct client_session *session UNUSED)
{
  verbose("pty request failed\n");

  return 1;
}

struct client_session_action client_request_pty =
  { STATIC_HEADER, 0,
    do_action_pty_start, do_action_pty_success, do_action_pty_failure };
