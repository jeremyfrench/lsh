/* unix_process.c
 *
 * Process-related functions on UN*X
 *
 * $Id$
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

#include "reaper.h"

#include "format.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"

#include <errno.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/wait.h>

#include <signal.h>

#if WITH_UTMP
# if HAVE_UTMP_H
#  include <utmp.h>
# endif

# if HAVE_UTMPX_H
#  include <utmpx.h>
# endif
#else /* !WITH_UTMP */
  /* Dummy definition, with enough information for logwtmp */
  struct utmp { char ut_line[17]; };
#endif

#if HAVE_LIBUTIL_H
# include <libutil.h>
#endif

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
	  werror("do_kill_process: kill failed (errno = %i): %z\n",
		 errno, STRERROR(errno));
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

  /* No need to signal the process. */
  self->process->alive = 0;

  EXIT_CALLBACK(self->c, signaled, core, value);
};

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


/* GABA:
   (class
     (name utmp_cleanup)
     (super exit_callback)
     (vars
       (utmp . "struct utmp")
       (c object exit_callback)))
*/

#if WITH_UTMP
static void
do_utmp_cleanup(struct exit_callback *s,
		int signaled, int core, int value)
{
  CAST(utmp_cleanup, self, s);

#if HAVE_UTMP_H
  self->utmp.ut_type = DEAD_PROCESS;
  
#if HAVE_STRUCT_UTMP_UT_EXIT
  self->utmp.ut_exit.e_exit = signaled ? 0 : value;
  self->utmp.ut_exit.e_termination = signaled ? value : 0;
#endif
#if HAVE_PUTUTLINE
  if (!pututline(&self->utmp))
    werror("Updating utmp failed (errno = %i): %z\n",
	   errno, STRERROR(errno));
#endif
#endif /* HAVE_UTMP_H */
#if HAVE_LOGWTMP
  logwtmp(self->utmp.ut_line, "", "");
#endif
  EXIT_CALLBACK(self->c, signaled, core, value);
}

static void
lsh_strncpy(char *dst, unsigned n, struct lsh_string *s)
{
  unsigned length = MIN(n - 1, s->length);
  memcpy(dst, s->data, length);
  dst[length] = '\0';
}
#define CP(dst, src) lsh_strncpy(dst, sizeof(dst), src);

static void
strip_tty_name(size_t size, char *dst, struct lsh_string *tty)
{
  size_t length = tty->length;
  char *src = tty->data;
  if (length >= 5 && !memcmp(src, "/dev/", 5))
    {
      length -= 5;
      src += 5;
    }
  if (length > size - 1)
    length = size - 1;

  memcpy(dst, src, length);
  dst[length] = 0;
}

#define CP_TTY(dst, src) strip_tty_name(sizeof(dst), dst, src)

static struct exit_callback *
utmp_book_keeping(struct lsh_string *name,
		  int login,
		  pid_t pid,
		  struct address_info *peer,
		  struct lsh_string *tty,
		  struct exit_callback *c)
{
  NEW(utmp_cleanup, cleanup);
  
  cleanup->super.exit = do_utmp_cleanup;
  cleanup->c = c;

  memset(&cleanup->utmp, 0, sizeof(cleanup->utmp));

  /* utmp->ut_line exists even in our dummy utmp struct */
  CP_TTY(cleanup->utmp.ut_line, tty);
  
#if HAVE_UTMP_H
  cleanup->utmp.ut_type = login ? LOGIN_PROCESS : USER_PROCESS;
  CP(cleanup->utmp.ut_line, tty);
  
#if HAVE_STRUCT_UTMP_UT_PID
  cleanup->utmp.ut_pid = pid;
#endif

#if HAVE_STRUCT_UTMP_UT_NAME
  CP(cleanup->utmp.ut_name, name);
#endif

  /* FIXME: Perform a reverse lookup.
   * Also use ut_addr and ut_addr_v6 */
#if HAVE_STRUCT_UTMP_UT_HOST
  CP(cleanup->utmp.ut_host, peer->ip);
#endif

#if HAVE_PUTUTLINE
  if (!pututline(&cleanup->utmp))
    werror("pututline failed (errno = %i): %z\n",
	   errno, STRERROR(errno));
#endif

#endif /* HAVE_UTMP_H */
  
#if HAVE_LOGWTMP
  logwtmp(cleanup->utmp.ut_line,
	  lsh_get_cstring(name),
	  lsh_get_cstring(peer->ip));
#endif /* HAVE_LOGWTMP */
  
  return &cleanup->super;
}
#endif /* WITH_UTMP */

struct lsh_process *
unix_process_setup(pid_t pid, int login, 
		   struct lsh_user *user,
		   struct exit_callback **c,
		   struct address_info *peer,
		   struct lsh_string *tty)
{
  struct lsh_process *process = make_unix_process(pid, SIGHUP);

#if WITH_UTMP
  if (tty)
    *c = utmp_book_keeping(user->name, pid, login, peer, tty, *c);
#endif

  *c = make_logout_notice(&process->super, *c);

  return process;
}
