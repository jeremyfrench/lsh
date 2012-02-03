/* unix_process.c
 *
 * Process-related functions on UN*X
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "environ.h"
#include "format.h"
#include "lsh_string.h"
#include "lsh_process.h"
#include "pty-helper.h"
#include "reaper.h"
#include "server_pty.h"
#include "werror.h"
#include "xalloc.h"

/* For lack of a better place */
#define GABA_DEFINE
# include "lsh_process.h.x"
#undef GABA_DEFINE

#include "unix_process.c.x"

/* GABA:
   (class
     (name unix_process)
     (super lsh_process)
     (vars
       (pid . pid_t)
       ; Signal used for killing the process.
       (signal . int)))
*/

static void
do_kill_process(struct resource *r)
{
  CAST(unix_process, self, r);

  if (self->super.super.alive)
    {
      self->super.super.alive = 0;
      /* NOTE: This function only makes one attempt at killing the
       * process. An improvement would be to install a callout handler
       * which will kill -9 the process after a delay, if it hasn't died
       * voluntarily. */

      if (kill(self->pid, self->signal) < 0)
	{
	  werror("do_kill_process: kill failed: %e.\n", errno);
	}
    }
}

static int
do_signal_process(struct lsh_process *s, int signal)
{
  CAST(unix_process, self, s);
  
  return self->super.super.alive
    && (kill(self->pid, signal) == 0);
}


static struct lsh_process *
make_unix_process(pid_t pid, int signal)
{
  NEW(unix_process, self);

  trace("unix_process.c: make_unix_process\n");
  
  init_resource(&self->super.super, do_kill_process);
  self->super.signal = do_signal_process;
  
  self->pid = pid;
  self->signal = signal;

  return &self->super;
}

static int
send_helper_request(int helper_fd, int ref,
		    enum pty_request_type type,
		    int fd)
{
  struct pty_message msg;
  int err;

  memset(&msg, 0, sizeof(msg));

  msg.header.type = type;
  msg.header.ref = ref;
  msg.header.length = 0;
  msg.has_creds = 1;

  msg.creds.uid = getuid();
  msg.creds.gid = getgid();
  msg.creds.pid = getpid();
  
  msg.fd = fd;

  err = pty_send_message(helper_fd, &msg);
  if (err)
    {
      werror("Sending message to pty helper failed: %e.\n", err);
      return -1;
    }
  err = pty_recv_message(helper_fd, &msg);
  if (err != 0)
    {
      if (err < 0)
	werror("Unexpected end of file from pty helper.\n");
      else
	werror("Receiving message from pty helper failed: %e.\n", err);
      return -1;
    }
  if (msg.fd >= 0)
    close(msg.fd);
  if (msg.header.type)
    {
      werror("Pty helper operation failed: %e.\n", msg.header.type);
      return -1;
    }
  return msg.header.ref;
}

/* GABA:
   (class
     (name logout_notice)
     (super exit_callback)
     (vars
       (process object resource)
       (c object exit_callback)       
       (helper_fd . int)
       (helper_ref . int)))
*/

static void
do_logout_notice(struct exit_callback *s,
		 int signaled, int core, int value)
{
  CAST(logout_notice, self, s);

  trace("unix_process: do_logout_notice\n");

  /* No need to signal the process. */
  self->process->alive = 0;

  if (self->helper_fd != -1)
    {
      /* FIXME: Pass termination status? */
      send_helper_request(self->helper_fd,
			  self->helper_ref,
			  PTY_REQUEST_LOGOUT,
			  -1);
    }
  EXIT_CALLBACK(self->c, signaled, core, value);
}

static struct exit_callback *
make_logout_notice(struct resource *process,
		   struct exit_callback *c,
		   int helper_fd, int helper_ref)
{
  NEW(logout_notice, self);
  self->super.exit = do_logout_notice;
  self->process = process;
  self->c = c;
  self->helper_fd = helper_fd;
  self->helper_ref = helper_ref;

  return &self->super;
}

static void
safe_close(int fd)
{
  if (fd != -1 && close(fd) < 0)
    werror("close failed: %e.\n", errno);
}

static const char *
format_env_pair(const char *name, const char *value)
{
  return lsh_get_cstring(ssh_format("%lz=%lz", name, value));
}

/* Helper functions for the process spawning. NOTE: Most of the setup
   of the environment is done by lshd-userauth; but we need to modify
   it here, in order to set up TERM and DISPLAY. */
static int
exec_shell(struct spawn_info *info)
{
  /* Environment consists of SHELL, other inherited values, caller's
     values, and a terminating NULL. */
#define INHERIT_ENV 5
  const char *inherited[INHERIT_ENV] =
    {
      ENV_HOME, ENV_USER, ENV_LOGNAME, ENV_TZ, ENV_SSH_CLIENT
    };
  const char *shell;
  
  unsigned i;
  unsigned j;
  const char **envp = alloca(sizeof(char *) * (info->env_length + INHERIT_ENV + 2));

  i = 0;
  
  shell = getenv(ENV_SHELL);
  if (!shell)
    {
      werror("exec_shell: No login shell???\n");
      return 0;
    }

  envp[i++] = format_env_pair(ENV_SHELL, shell);
  
  for (j = 0; j < INHERIT_ENV; j++)
    {
      const char *name = inherited[j];
      const char *value = getenv(name);
      if (value)
	envp[i++] = format_env_pair(name, value);
    }
  for (j = 0; j < info->env_length; j++)
    envp[i++] = format_env_pair(info->env[j].name, info->env[j].value);

  envp[i++] = NULL;

  if (!info->argv)
    {
      info->argv = alloca(sizeof(char *) * 2);
      info->argv[1] = NULL;
    }

  if (info->login)
    {
      /* Fixup argv[0], so that it starts with a dash */
      const char *p;
      char *s;
      size_t length = strlen(shell);

      /* We can't alloca unlimited storage */
      if (length > 1000)
	{
	  werror("exec_shell: shell name far too long.\n");
	  return 0;
	}
      
      debug("exec_shell: fixing up name of shell...\n");
      
      s = alloca(length + 2);

      /* Make sure that the shell's name begins with a -. */
      p = strrchr (shell, '/');
      if (!p)
	p = shell;
      else
	p ++;

      s[0] = '-';
      strncpy (s + 1, p, length + 1);
      info->argv[0] = s;
    }
  else
    info->argv[0] = shell;

  debug("exec_shell: argv0 = '%z'.\n", info->argv[0]);

  trace("exec_shell: before exec\n");
  execve(shell, (char **) info->argv, (char**) envp);

  werror("exec_shell: exec of `%z' failed: %e.\n", shell, errno);
  return 0;  
}

static void
spawn_error(struct spawn_info *info,
	    int helper_fd, int helper_ref)
{
  trace("unix_process: spawn_error\n");

  safe_close(info->in[0]);  safe_close(info->in[1]);
  safe_close(info->out[0]); safe_close(info->out[1]);
  safe_close(info->err[0]);
  /* Allow the client's stdout and stderr to be the same fd, e.g.
   * both /dev/null. */
  if (info->err[1] != info->out[1])
    safe_close(info->err[1]);

  if (helper_fd != -1)
    send_helper_request(helper_fd, helper_ref, PTY_REQUEST_DESTROY, -1);
}

/* Parent processing */
static struct lsh_process *
spawn_parent(struct spawn_info *info,
	     struct exit_callback *c,
	     pid_t child, int sync,
	     int helper_fd, int helper_ref)
{
  /* Parent */
  struct lsh_process *process;
  char dummy;
  int res;
      
  /* Close the child's fd:s, except ones that are -1 */
  safe_close(info->in[0]);
  safe_close(info->out[1]);

  /* Allow the client's stdout and stderr to be the same fd, e.g.
   * both /dev/null. */
  if (info->err[1] != info->out[1])
    safe_close(info->err[1]);

  /* On Solaris, reading the master side of the pty before the
   * child has opened the slave side of it results in EINVAL. We
   * can't have that, so we'll wait until the child has opened the
   * tty, after which it should close its end of the
   * syncronization pipe, and our read will return 0.
   *
   * It also helps for syncronization of the parent's and the child's
   * requests to the pty helper process. */
      
  do
    res = read(sync, &dummy, 1);
  while (res < 0 && errno == EINTR);

  safe_close(sync);

  trace("spawn_parent: after sync\n");

  process = make_unix_process(child, SIGHUP);
  reaper_handle(child, make_logout_notice(&process->super, c,
					  helper_fd, helper_ref));

  trace("spawn_parent: parent after process setup\n");

  return process;
}

static void
spawn_child(struct spawn_info *info, int sync,
	    int helper_fd, int helper_ref)
{
  int tty = -1;

  trace("unix_process: spawn_child\n");

  /* We want to be a process group leader */
  if (setsid() < 0)
    {
      werror("setsid failed, already process group leader?: %e.\n", errno);
      _exit(EXIT_FAILURE);
    }
      
#if WITH_PTY_SUPPORT
  if (info->pty)
    {
      debug("spawn_child: Opening slave tty...\n");
      if ( (tty = pty_open_slave(info->pty)) < 0)
	{
	  werror("Can't open controlling tty for child!\n");
	  _exit(EXIT_FAILURE);
	}
      else
	debug("spawn_child: Opening slave tty succeeded.\n");
    }
#endif /* WITH_PTY_SUPPORT */

  trace("spawn_child: after pty\n");

  if (helper_fd != -1)
    send_helper_request(helper_fd, helper_ref, PTY_REQUEST_LOGIN, -1);

  /* Now any tty processing is done, so notify our parent by closing
   * the syncronization pipe. FIXME: There's some race condition in
   * signalling EOF on the pty (^D written to the master side mangled
   * into NUL on the reading side. Observed on linux-2.6.16. Not
   * solved; delaying the close a little using io_set_close_on_exec
   * made no difference). */

  safe_close (sync);

#define DUP_FD_OR_TTY(src, dst) dup2((src) >= 0 ? (src) : tty, dst)

  if (DUP_FD_OR_TTY(info->in[0], STDIN_FILENO) < 0)
    {
      werror("Can't dup stdin!\n");
      _exit(EXIT_FAILURE);
    }

  if (DUP_FD_OR_TTY(info->out[1], STDOUT_FILENO) < 0)
    {
      werror("Can't dup stdout!\n");
      _exit(EXIT_FAILURE);
    }

  trace("spawn_child: child before stderr dup\n");
  if (!dup_error_stream())
    {
      werror("unix_user.c: Failed to dup old stderr. Bye.\n");
      set_error_ignore();
    }

  if (DUP_FD_OR_TTY(info->err[1], STDERR_FILENO) < 0)
    {
      werror("Can't dup stderr!\n");
      _exit(EXIT_FAILURE);
    }
#undef DUP_FD_OR_TTY
      
  trace("spawn_child: after stderr dup\n");

  /* Close all the fd:s, except ones that are -1 */
  safe_close(info->in[0]);
  safe_close(info->in[1]);
  safe_close(info->out[0]);
  safe_close(info->out[1]);
  safe_close(info->err[0]);
  /* Allow the client's stdout and stderr to be the same fd, e.g.
   * both /dev/null. */
  if (info->err[1] != info->out[1])
    safe_close(info->err[1]);

  safe_close(tty);  
}

struct lsh_process *
spawn_shell(struct spawn_info *info, int helper_fd,
	    struct exit_callback *c)
{
  /* Pipe used for syncronization. */
  int sync[2];
  pid_t child;
  int helper_ref = -1;

  trace("unix_process: spawn_shell\n");
  
  if (!lsh_make_pipe(sync))
    {
      werror("do_spawn: Failed to create syncronization pipe.\n");
      return NULL;
    }

  if (helper_fd != -1)
    {
      helper_ref
	= send_helper_request(helper_fd, -1,
			      PTY_REQUEST_CREATE,
			      info->pty ? info->pty->master : -1);
      if (helper_ref < 0)
	/* We can't use the helper. */
	helper_fd = -1;
    }

  child = fork();
  if (child < 0)
    {
      werror("spawn_shell: fork failed: %e.\n", errno);
      safe_close(sync[0]); safe_close(sync[1]);

      spawn_error(info, helper_fd, helper_ref);

      return NULL;
    }
  else if (child)
    {
      /* Parent */
      trace("spawn_shell: parent process\n");

      safe_close(sync[1]);
      return spawn_parent(info, c, child, sync[0], helper_fd, helper_ref);
    }
  else
    {
      /* Child */
      safe_close(sync[0]);
      spawn_child(info, sync[1], helper_fd, helper_ref);

      exec_shell(info);
      _exit(EXIT_FAILURE);
    }
}
