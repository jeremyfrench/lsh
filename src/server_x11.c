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

#include "format.h"
#include "reaper.h"
#include "resource.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#define GABA_DEFINE
#include "server_x11.h.x"
#undef GABA_DEFINE

#include "server_x11.c.x"

#if WITH_X11_FORWARD

#define XAUTH_DEBUG_TO_STDERR 0

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
do_xauth_exit(struct exit_callback *s, int signaled,
	      int core UNUSED, int value)
{
  CAST(xauth_exit_callback, self, s);
  
  if (signaled || value)
    {
      /* xauth failed */
      const struct exception xauth_failed
	= STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "xauth failed");
      EXCEPTION_RAISE(self->e, &xauth_failed);
      if (signaled)
	werror("xauth invocation failed: Signal %d\n", value);
      else
	werror("xauth invocation failed: exit code: %d\n", value);
    }
  else
    /* NOTE: Return value is ignored. */
    COMMAND_RETURN(self->c, NULL);
}

static struct exit_callback *
make_xauth_exit_callback(struct command_continuation *c,
			 struct exception_handler *e)
{
  NEW(xauth_exit_callback, self);
  self->super.exit = do_xauth_exit;
  self->c = c;
  self->e = e;

  return &self->super;
}

/* NOTE: We don't check the arguments for spaces or other magic
 * characters. The xauth process in unprivileged, and the user is
 * properly authenticated to call it with arbitrary commands. We still
 * check for NUL characters, though. */
static int
bad_string(UINT32 length, const UINT8 *data)
{
  return !!memchr(data, '\0', length);
}

/* FIXME: Use autoconf */
#define XAUTH_PROGRAM "/usr/X11R6/bin/xauth"

/* On success, returns 1 and sets *DISPLAY and *XAUTHORITY */
struct server_x11_info *
server_x11_setup(struct ssh_channel *channel, struct lsh_user *user,
		 UINT32 protocol_length, const UINT8 *protocol,
		 UINT32 cookie_length, const UINT8 *cookie,
		 UINT32 screen,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  /* Get a free socket under /tmp/.X11-unix/ */
  UINT32 display_number = 17;

  struct lsh_string *display;
  struct lsh_string *xauthority;
  
  const char *tmp;

  /* FIXME: Bind socket, set up forwarding */
  struct lsh_fd *socket = NULL;

  if (bad_string(protocol_length, protocol))
    {
      werror("server_x11_setup: Bogus protocol name.\n");
      return NULL;
    }
  
  if (bad_string(cookie_length, cookie))
    {
      werror("server_x11_setup: Bogus cookie.\n");
      return NULL;
    }
  
  if (cookie_length < X11_MIN_COOKIE_LENGTH)
    {
      werror("server_x11_setup: Cookie too small.\n");
      return NULL;
    }

  tmp = getenv("TMPDIR");
  if (!tmp)
    tmp = "tmp";
  
  display = ssh_format(":%di.%di", display_number, screen);
  xauthority = ssh_format("/%lz/.lshd.%lS.Xauthority", tmp, user->name);

  {
    struct spawn_info spawn;
    const char *args[2] = { "-c", XAUTH_PROGRAM };
    const struct env_value env[1] =
      { {"XAUTHORITY", xauthority } };

    struct lsh_process *process;

    int null;

    memset(&spawn, 0, sizeof(spawn));
    /* FIXME: Arrange that stderr data (and perhaps stdout data as
     * well) is sent as extrended data on the channel. To do that, we
     * need another channel flag to determine whether or not EOF
     * should be sent when the number of sources gets down to 0. */
#if XAUTH_DEBUG_TO_STDERR
    null = dup(STDERR_FILENO);
#else
    null = open("/dev/null", O_WRONLY);
#endif
    if (null < 0)
      goto fail;

    /* [0] for reading, [1] for writing */
    if (!lsh_make_pipe(spawn.in))
      {
	close(null);
	goto fail;
      }
    spawn.out[0] = -1; spawn.out[1] = null;
    spawn.err[0] = -1; spawn.err[1] = null;
    
    spawn.peer = NULL;
    spawn.pty = NULL;
    spawn.login = 0;
    spawn.argc = 2;
    spawn.argv = args;
    spawn.env_length = 1;
    spawn.env = env;

    process = USER_SPAWN(user, &spawn, make_xauth_exit_callback(c, e));
    if (process)
      {
	NEW(server_x11_info, info);
	static const struct report_exception_info report =
	  STATIC_REPORT_EXCEPTION_INFO(EXC_IO, EXC_IO, "writing xauth stdin");

	struct lsh_fd *in
	  = io_write(make_lsh_fd(spawn.in[1],
				 "xauth stdin",
				 make_report_exception_handler
				 (&report, e, HANDLER_CONTEXT)),
		     1024, NULL);

	A_WRITE(&in->write_buffer->super,
		/* NOTE: We pass arbitrary data to the xauth process,
		 * if the user so wish. */
		 ssh_format("add %lS %ls %ls\n",
			   display,
			   protocol_length, protocol,
			   cookie_length, cookie));
	close_fd_write(in);

	remember_resource(channel->resources, &process->super);
	remember_resource(channel->resources, &in->super);	
	
	info->display = display;
	info->xauthority = xauthority;
	
	return info;
      }
    else
      {
	close(spawn.in[0]);
	close(spawn.in[1]);
      fail:
	lsh_string_free(display);
	lsh_string_free(xauthority);
	return NULL;
      }
  }
}

#endif /* WITH_X11_FORWARD */
