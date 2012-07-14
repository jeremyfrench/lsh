/* reaper.c
 *
 * Handle child processes.
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "reaper.h"

#include "alist.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "reaper.h.x"
#undef GABA_DEFINE

#include "reaper.c.x"

/* GABA:
   (class
     (name reaper_callback)
     (super lsh_callback)
     (vars
       (children object alist)))
*/

/* We use a global variable for this. The SIGCHLD handler is global anyway. */
static struct reaper_callback *
reaper_global = NULL;

static void
do_reaper_callback(struct lsh_callback *s)
{
  CAST(reaper_callback, self, s);
  
  pid_t pid;
  int status;

  while( (pid = waitpid(-1, &status, WNOHANG)) )
    {
      if (pid > 0)
	{
	  int signaled;
	  int value;
	  int core;
	  struct exit_callback *callback;
	  
	  if (WIFEXITED(status))
	    {
	      verbose("Child %i died with exit code %i.\n",
		      pid, WEXITSTATUS(status));
	      signaled = 0;
	      core = 0;
	      value = WEXITSTATUS(status);
	    }
	  else if (WIFSIGNALED(status))
	    {
	      verbose("Child %i killed by signal %i.\n",
		      pid, WTERMSIG(status));
	      signaled = 1;
#ifdef WCOREDUMP
	      core = !!WCOREDUMP(status);
#else
	      core = 0;
#endif
	      value = WTERMSIG(status);
	    }
	  else
	    fatal("Child died, but neither WIFEXITED or WIFSIGNALED is true.\n");

	  {
	    CAST_SUBTYPE(exit_callback, c, ALIST_GET(self->children, pid));
	    callback = c;
	  }
	  
	  if (callback)
	    {
	      ALIST_SET(self->children, pid, NULL);
	      EXIT_CALLBACK(callback, signaled, core, value);
	    }
	  else
	    {
	      if (WIFSIGNALED(status))
		werror("Unregistered child %i killed by signal %i.\n",
		       pid, value);
	      else
		werror("Unregistered child %i died with exit status %i.\n",
		       pid, value);
	    }
	}
      else switch(errno)
	{
	case EINTR:
	  debug("reaper.c: waitpid returned EINTR.\n");
	  break;
	case ECHILD:
	  /* No more child processes */
	  return;
	default:
	  fatal("reaper.c: waitpid failed: %e.\n", errno);
	}
    }
}

static struct reaper_callback *
make_reaper_callback(void)
{
  NEW(reaper_callback, self);
  self->super.f = do_reaper_callback;
  self->children = make_linked_alist(0, -1);

  return self;
}

void
reaper_init(void)
{
  assert(reaper_global == NULL);
  reaper_global = make_reaper_callback();
  io_signal_handler(SIGCHLD, &reaper_global->super);
}

void
reaper_handle(pid_t pid, struct exit_callback *callback)
{
  assert (reaper_global);
  trace("reaper_handle: pid = %i.\n", (uint32_t) pid);

  ALIST_SET(reaper_global->children, pid, &callback->super);
}

