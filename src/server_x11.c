/* server_x11.c
 *
 * $id:$
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2002 Niels Möller
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

#include "server_x11.h"

#include "reaper.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "server_x11.h.x"
#undef GABA_DEFINE

#include "server_x11.c.x"

#if WITH_X11_FORWARD

#define X11_MIN_COOKIE_LENGTH 10

/* GABA:
   (class
     (name xauth_exit_callback)
     (super exit_callback)
     (vars
       (c object command_continuation)
       (e object exception_handler)))
*/

static void
do_xauth_exit(struct exit_callback *s, int signaled, int core, int value)
{
  CAST(xauth_exit_callback, self, s);
  
  if (signaled || value)
    {
      /* xauth failed */
      const struct exception xauth_failed
	= STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "xauth failed");
      EXCEPTION_RAISE(self->e, &xauth_failed);
    }
  else
    /* NOTE: Return value is ignored. */
    COMMAND_RETURN(c, NULL);
}

static struct exit_callback *
make_xauth_exit_callback(struct command_continuation *c,
			 struct exception_handler *e)
{
  NEW(xauth_exit_callback, self);
  self->super.exit = do_xauth_exit;
  self->c = c;
  self->e = e;
}

/* On success, returns 1 and sets *DISPLAY and *XAUTHORITY */
struct server_x11_info *
server_x11_setup(struct ssh_channel *channel, struct lsh_user *user,
		 const struct lsh_string *protocol,
		 const struct lsh_string *cookie,
		 UINT32 screen)
{
  /* Get a free socket under /tmp/.X11-unix/ */
  UINT32 display_number = 17;

  struct lsh_string *display;
  struct lsh_string *xauthority;
  
  struct server_x11_info *info;
  
  const char *tmp;

  /* FIXME: Bind socket, set up forwarding */
  struct lsh_fd *socket = NULL;

  if (!lsh_get_cstring(protocol))
    {
      werror("server_x11_setup: Bogus protocol name.\n");
      return NULL;
    }
  
  if (!lsh_get_cstring(cookie))
    {
      werror("server_x11_setup: Bogus cookie.\n");
      return NULL;
    }
  
  if (cookie->length < X11_MIN_COOKIE_LENGTH)
    {
      werror("server_x11_setup: Cookie too small.\n");
      return NULL;
    }

  tmp = getenv(TMPDIR);
  if (!tmp)
    tmp = "tmp";
  
  display = ssh_format("%di:%di", display_number, screen);
  xauthority = ssh_format("/%lz/.lshd.%lS.Xauthority", tmp, user->name);

  {
    struct spawn_info spawn;
    const char *args[5] = { "-c", "xauth $0 $1 $2",
			    lsh_get_cstring(*display),
			    lsh_get_cstring(protocol),
			    lsh_get_cstring(cookie) };
    const struct env_value env[1] =
      { {"XAUTHORITY", lsh_get_cstring(*xauthority) } };

    struct lsh_process *process;
    
    memset(&spawn, 0, sizeof(spawn));
    spawn->peer = NULL;
    spawn->pty = NULL;
    spawn->login = 0;
    spawn->argc = 5;
    spawn->argv = args;
    spawn->env_length = 1;
    spawn->env = env;

    process = USER_SPAWN(user, &spawn, make_xauth_exit_callback(c, e));
    if (process)
      {
	REMEMBER_RESOURCE(channel->resources, &process->super);
	NEW(server_x11_info, info);
	info->display = display;
	info->xauthority = xauthority;

	return info;
      }
    else
      {
	lsh_string_free(display);
	lsh_string_free(xauthority);
	return NULL;
      }
  }
}

#endif /* WITH_X11_FORWARD */
