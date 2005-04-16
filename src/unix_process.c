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


/* FIXME: Should this be done in configure instead? Doesn't hurt though */

#if WITH_UTMP
# if HAVE_UTMP_H
#  include <utmp.h>
#  ifndef WTMP_FILE
#   define WTMP_FILE "/var/adm/wtmp"
#  endif
# endif

# if HAVE_UTMPX_H
#  include <utmpx.h>
#  ifndef WTMPX_FILE
#   define WTMPX_FILE "/var/adm/wtmpx" 
#  endif
# endif
#endif

#if HAVE_LIBUTIL_H
# include <libutil.h>
#endif

#include "environ.h"
#include "format.h"
#include "lsh_string.h"
#include "lsh_process.h"
#include "reaper.h"
#include "server_pty.h"
#include "werror.h"
#include "xalloc.h"

/* For lack of a better place */
#define GABA_DEFINE
# include "lsh_process.h.x"
#undef GABA_DEFINE

#include "unix_process.c.x"

/* Figure out which flavour of utmp/utmpx to use. */
#if HAVE_UTMPX_H && HAVE_PUTUTXLINE
# define USE_UTMPX 1
# define PUTUTXLINE pututxline
# define GETUTXID   getutxid 
# define SETUTXENT setutxent 
# define UTMPX utmpx
# define UTMPX_UT_EXIT    HAVE_STRUCT_UTMPX_UT_EXIT
# define UTMPX_UT_EXIT_E_TERMINATION HAVE_STRUCT_UTMPX_UT_EXIT_E_TERMINATION
# define UTMPX_UT_EXIT___E_TERMINATION HAVE_STRUCT_UTMPX_UT_EXIT___E_TERMINATION
# define UTMPX_UT_EXIT_UT_TERMINATION HAVE_STRUCT_UTMPX_UT_EXIT_UT_TERMINATION
# define UTMPX_UT_PID     HAVE_STRUCT_UTMPX_UT_PID
# define UTMPX_UT_USER    HAVE_STRUCT_UTMPX_UT_USER
# define UTMPX_UT_TV      HAVE_STRUCT_UTMPX_UT_TV_TV_SEC
# define UTMPX_UT_TIME    HAVE_STRUCT_UTMPX_UT_TIME
# define UTMPX_UT_ADDR    HAVE_STRUCT_UTMPX_UT_ADDR
# define UTMPX_UT_ADDR_V6 HAVE_STRUCT_UTMPX_UT_ADDR_V6
# define UTMPX_UT_HOST    HAVE_STRUCT_UTMPX_UT_HOST
# define UTMPX_UT_SYSLEN  HAVE_STRUCT_UTMPX_UT_SYSLEN
# define WTMPX            WTMPX_FILE
# if HAVE_UPDWTMPX
#   define UPDWTMPX updwtmpx
# endif
#else
# if HAVE_UTMP_H && HAVE_PUTUTLINE
#  define USE_UTMPX 1
#  define PUTUTXLINE pututline
#  define GETUTXID   getutid 
#  define SETUTXENT setutent 
#  define UTMPX utmp
#  define UTMPX_UT_EXIT    HAVE_STRUCT_UTMP_UT_EXIT
#  define UTMPX_UT_EXIT_E_TERMINATION HAVE_STRUCT_UTMP_UT_EXIT_E_TERMINATION
#  define UTMPX_UT_EXIT___E_TERMINATION HAVE_STRUCT_UTMP_UT_EXIT___E_TERMINATION
#  define UTMPX_UT_EXIT_UT_TERMINATION HAVE_STRUCT_UTMP_UT_EXIT_UT_TERMINATION
#  define UTMPX_UT_PID     HAVE_STRUCT_UTMP_UT_PID
#  define UTMPX_UT_USER    HAVE_STRUCT_UTMP_UT_USER
#  define UTMPX_UT_TV      HAVE_STRUCT_UTMP_UT_TV_TV_SEC
#  define UTMPX_UT_TIME    HAVE_STRUCT_UTMP_UT_TIME
#  define UTMPX_UT_ADDR    HAVE_STRUCT_UTMP_UT_ADDR
#  define UTMPX_UT_ADDR_V6 HAVE_STRUCT_UTMP_UT_ADDR_V6
#  define UTMPX_UT_HOST    HAVE_STRUCT_UTMP_UT_HOST
#  define UTMPX_UT_SYSLEN  HAVE_STRUCT_UTMP_UT_SYSLEN
#  define WTMPX            WTMP_FILE
#  if HAVE_UPDWTMP
#   define UPDWTMPX updwtmp
#  endif
# else
#  define USE_UTMPX 0
# endif
#endif

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
	  werror("do_kill_process: kill failed %e\n", errno);
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


struct lsh_process *
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

/* GABA:
   (class
     (name logout_notice)
     (super exit_callback)
     (vars
       (process object resource)
       (c object exit_callback)))
*/

static void
do_logout_notice(struct exit_callback *s,
		 int signaled, int core, int value)
{
  CAST(logout_notice, self, s);

  trace("unix_process: do_logout_notice\n");

  /* No need to signal the process. */
  self->process->alive = 0;

  EXIT_CALLBACK(self->c, signaled, core, value);
}

static struct exit_callback *
make_logout_notice(struct resource *process,
		   struct exit_callback *c)
{
  NEW(logout_notice, self);
  self->super.exit = do_logout_notice;
  self->process = process;
  self->c = c;

  return &self->super;
}

static void
safe_close(int fd)
{
  if (fd != -1 && close(fd) < 0)
    werror("close failed %e\n", errno);
}

static const char *
format_env_pair(const char *name, struct lsh_string *value)
{
  assert(lsh_get_cstring(value));
  return lsh_get_cstring(ssh_format("%lz=%lS", name, value));
}

static const char *
format_env_pair_c(const char *name, const char *value)
{
  return lsh_get_cstring(ssh_format("%lz=%lz", name, value));
}


/* Helper functions for the process spawning. */
int
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

  envp[i++] = format_env_pair_c(ENV_SHELL, shell);
  
  for (j = 1; j < INHERIT_ENV; j++)
    {
      const char *name = inherited[j];
      const char *value = getenv(name);
      if (value)
	envp[i++] = format_env_pair_c(name, value);
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

  werror("exec_shell: exec of `%z' failed %e\n", shell, errno);
  return 0;  
}

static void
spawn_error(struct spawn_info *info,
	    const int *sync)
{
  safe_close(sync[0]); safe_close(sync[1]);
  
  safe_close(info->in[0]);  safe_close(info->in[1]);
  safe_close(info->out[0]); safe_close(info->out[1]);
  safe_close(info->err[0]);
  /* Allow the client's stdout and stderr to be the same fd, e.g.
   * both /dev/null. */
  if (info->err[1] != info->out[1])
    safe_close(info->err[1]);
}

/* Parent processing */
static struct lsh_process *
spawn_parent(struct spawn_info *info,
	     struct exit_callback *c,
	     pid_t child,
	     const int *sync)
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

  safe_close(sync[1]);

  /* On Solaris, reading the master side of the pty before the
   * child has opened the slave side of it results in EINVAL. We
   * can't have that, so we'll wait until the child has opened the
   * tty, after which it should close its end of the
   * syncronization pipe, and our read will return 0.
   *
   * We need the syncronization only if we're actually using a
   * pty, but for simplicity, we do it every time. */
      
  do
    res = read(sync[0], &dummy, 1);
  while (res < 0 && errno == EINTR);

  safe_close(sync[0]);

  trace("spawn_parent: after sync\n");

  /* FIXME: Doesn't do any utmp/wtmp logging */
  process = make_unix_process(child, SIGHUP);
  reaper_handle(child, make_logout_notice(&process->super, c));

  trace("spawn_parent: parent after process setup\n");

  return process;
}

static void
spawn_child(struct spawn_info *info,
	    const int *sync)
{
  int tty = -1;

  /* We want to be a process group leader */
  if (setsid() < 0)
    {
      werror("setsid failed, already process group leader?\n"
	     "   %e\n", errno);
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
      
  /* Now any tty processing is done, so notify our parent by
   * closing the syncronization pipe. */
      
  safe_close(sync[0]); safe_close(sync[1]);

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
spawn_shell(struct spawn_info *info,
	    struct exit_callback *c)
{
  /* Pipe used for syncronization. */
  int sync[2];
  pid_t child;
  
  if (!lsh_make_pipe(sync))
    {
      werror("do_spawn: Failed to create syncronization pipe.\n");
      return NULL;
    }
  
  child = fork();
  if (child < 0)
    {
      werror("spawn_shell: fork failed %e\n", errno);
      spawn_error(info, sync);

      return NULL;
    }
  else if (child)
    {
      /* Parent */
      trace("spawn_shell: parent process\n");

      return spawn_parent(info, c, child, sync);
    }
  else
    { /* Child */
      spawn_child(info, sync);
      
      exec_shell(info);
      _exit(EXIT_FAILURE);
    }
}

/* At the moment, utmp and wtmp can't work at all, due to lack of privileges. */
#if 0


/* GABA:
   (class
     (name utmp_cleanup)
     (super exit_callback)
     (vars
       (id string)
       (line string)
       (c object exit_callback)))
*/

#if WITH_UTMP

/* Helper macros for assigning utmp fields */
#define CLEAR(dst) (memset(&(dst), 0, sizeof(dst)))

static void
lsh_strncpy(char *dst, unsigned n, struct lsh_string *s)
{  
  unsigned length = MIN(n, lsh_string_length(s));
  memcpy(dst, lsh_string_data(s), length);
  if (length < n)
    dst[length] = '\0';
}
#define CP(dst, src) lsh_strncpy(dst, sizeof(dst), src)

static void
do_utmp_cleanup(struct exit_callback *s,
		int signaled, int core, int value)
{
  CAST(utmp_cleanup, self, s);

#if USE_UTMPX
  struct UTMPX entry;
#ifndef HAVE_LOGWTMP
  struct UTMPX wc;
  struct UTMPX *old;
#endif

  trace("unix_process.c: do_utmp_cleanup (HAVE_UTMPX_H) \n");

  /* Rewind the database */
  SETUTXENT();

  /* Start by clearing the whole entry */
  memset(&entry, 0, sizeof(entry));

  /* FIXME: Are there systems without ut_id? Do we care? */
  CP(entry.ut_id, self->id);
  entry.ut_type = DEAD_PROCESS;  

  /* The memset has cleared all fields so we need only set those
   * entries that shouldn't be 0 */

#if UTMPX_UT_EXIT
# if UTMPX_UT_EXIT_E_TERMINATION
  entry.ut_exit.e_exit = signaled ? 0 : value;
  entry.ut_exit.e_termination = signaled ? value : 0;
# elif UTMPX_UT_EXIT_UT_TERMINATION
  /* Names use on tru64 */
  entry.ut_exit.ut_exit = signaled ? 0 : value;
  entry.ut_exit.ut_termination = signaled ? value : 0;
# elif UTMPX_UT_EXIT___E_TERMINATION
  /* HPUX uses these odd names in struct utmpx */
  entry.ut_exit.__e_exit = signaled ? 0 : value;
  entry.ut_exit.__e_termination = signaled ? value : 0;
# elif __GNUC__
#  warning utmp.ut_exit exists, but no known sub attributes  
# endif
#endif

#ifndef HAVE_LOGWTMP

  /* Mumble. For utmp{,x} we want as much as possible of the entry to
   * be cleared, but for wtmp{,x} we want to retain as much
   * information as possible, so we get the entry from utmp{,x}, put
   * the cleared one to utmp{,x}.  */

  trace("unix_process.c: do_utmp_cleanup without logwtmp, looking up old entry\n");
  
  old = GETUTXID( &entry );
    
  if( !old ) /* getut{,x}id failed? */
    {
      debug("unix_process.c: do_utmp_cleanup getut{,x}id failed\n");

      wc = entry; /* Copy the entry we're going to write and fill it in as much as we can */
      CP(wc.ut_line, self->line);
    }
  else
    wc = *old; /* Copy the old entry (on Solaris, putut{,x}line invalidates *old) */
  
#endif /* HAVE_LOGWTMP */
      
  if (!PUTUTXLINE(&entry))
    werror("Updating utmpx for logout failed %e\n", errno);

#ifndef HAVE_LOGWTMP

  /* Calculate timestamp for wtmp */

# if UTMPX_UT_TV
  gettimeofday(&wc.ut_tv, NULL); /* Ignore the timezone */
# else
#  if UTMPX_UT_TIME
  time(&wc.ut_time);
#  endif /* UTMPX_UT_TIME */
# endif /* UTMPX_UT_TV */

  old->ut_type = DEAD_PROCESS; /* Mark as dead */

#endif /* HAVE_LOGWTMP */

#if HAVE_LOGWTMP
  logwtmp(lsh_get_cstring(self->line), "", "");
#else /* HAVE_LOGWTMP */
# ifdef UPDWTMPX
  UPDWTMPX(WTMPX, &wc); 
# endif
#endif /* HAVE_LOGWTMP */
#endif /* USE_UTMPX */

  EXIT_CALLBACK(self->c, signaled, core, value);
}

static struct utmp_cleanup *
make_utmp_cleanup(struct lsh_string *tty,
		  struct exit_callback *c)
{
  NEW(utmp_cleanup, self);
  uint32_t length = lsh_string_length(tty);
  const uint8_t *data = lsh_string_data(tty);

  self->super.exit = do_utmp_cleanup;
  self->c = c;

  if (length > 5 && !memcmp(data, "/dev/", 5))
    {
      data +=5; length -= 5;
    }
  self->line = ssh_format("%ls", length, data);

  /* Construct ut_id following the linux utmp(5) man page:
   *
   *   line = "pts/17" => id = "p17",
   *   line = "ttyxy"  => id = "xy" (usually, x = 'p')
   *
   * NOTE: This is different from what rxvt does on my system, it sets
   * id = "vt11" if line = "pts/17".
   */
  if (length > 4 && !memcmp(data, "pts/", 4))
    { data += 4; length -= 4; }
  else if (length > 3 && !memcmp(data, "tty", 3))
    { data += 3; length -= 3; }
  else
    {/* If the patterns above don't match, we set ut_id empty */
      length = 0;
    }
  self->id = ssh_format("%ls", length, data);

  return self;
}

static struct exit_callback *
utmp_book_keeping(struct lsh_string *name,
		  pid_t pid,
		  struct address_info *peer,
		  struct lsh_string *tty,
		  struct exit_callback *c)
{
  struct utmp_cleanup *cleanup = make_utmp_cleanup(tty, c);

#if USE_UTMPX
  struct UTMPX entry;
  memset(&entry, 0, sizeof(entry));

  SETUTXENT(); /* Rewind the database */

  trace("unix_process.c: utmp_book_keeping\n");

  /* Do not look for an existing entry, but trust putut{,x}line to
   * reuse old entries if appropiate */

  entry.ut_type = USER_PROCESS;

  CP(entry.ut_line, cleanup->line);
  CP(entry.ut_id, cleanup->id);

#if UTMPX_UT_PID
  entry.ut_pid = pid;
#endif

#if UTMPX_UT_USER
  CP(entry.ut_user, name);
#endif

#if UTMPX_UT_TV
  gettimeofday(&entry.ut_tv, NULL); /* Ignore the timezone */
#else
# if UTMPX_UT_TIME
  time(&entry.ut_time);
# endif
#endif
  
  trace("unix_process.c: utmp_book_keeping, after name (HAVE_UTMPX_H)\n");

  /* FIXME: We should store real values here. */
#if UTMPX_UT_ADDR
  CLEAR(entry.ut_addr);
#endif
#if UTMPX_UT_ADDR_V6
  CLEAR(entry.ut_addr_v6);
#endif
  
  /* FIXME: Perform a reverse lookup. */
#if UTMPX_UT_HOST
  CP(entry.ut_host, peer->ip);
#if UTMPX_UT_SYSLEN

  /* ut_syslen is the significant length of ut_host (including NUL),
   * i.e. the lesser of the length of peer->ip+1 and available storage 
   */

  entry.ut_syslen = MIN(sizeof(entry.ut_host),
			lsh_string_length(peer->ip) + 1);

#endif /* UTMPX_UT_SYSLEN */
#endif /* UTMPX_UT_HOST */

  trace("unix_process.c: utmp_book_keeping, after host (HAVE_UTMPX_H)\n");

  if (!PUTUTXLINE(&entry))
    werror("Updating utmp for login failed %e\n", errno);

  trace("unix_process.c: utmp_book_keeping, after pututline (HAVE_UTMPX_H)\n");

#if HAVE_LOGWTMP
  logwtmp(lsh_get_cstring(cleanup->line),
	  lsh_get_cstring(name),
	  lsh_get_cstring(peer->ip));
#else /* HAVE_LOGWTMP */
# ifdef UPDWTMPX
  UPDWTMPX(WTMPX, &entry); 
# endif
#endif /* HAVE_LOGWTMP */

#endif /* USE_UTMPX */

  trace("unix_process.c: utmp_book_keeping, after logwtmp\n");
  
  return &cleanup->super;
}
#endif /* WITH_UTMP */

struct lsh_process *
unix_process_setup(pid_t pid,
		   struct lsh_user *user,
		   struct exit_callback **c,
		   struct address_info *peer,
		   struct lsh_string *tty)
{
  struct lsh_process *process = make_unix_process(pid, SIGHUP);

  trace("unix_process.c: unix_process_setup\n");
  
#if WITH_UTMP
  if (tty)
    *c = utmp_book_keeping(user->name, pid, peer, tty, *c);
#endif

  trace("unix_process.c: unix_process_setup, after utmp\n");
  
  *c = make_logout_notice(&process->super, *c);

  return process;
}
#endif
