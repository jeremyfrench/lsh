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
  unsigned length = MIN(n, s->length);
  memcpy(dst, s->data, length);
  if (length < n)
    dst[length] = '\0';
}
#define CP(dst, src) lsh_strncpy(dst, sizeof(dst), src)

static void
do_utmp_cleanup(struct exit_callback *s,
		int signaled, int core, int value)
{
  CAST(utmp_cleanup, self, s);

#if HAVE_UTMP_H
  struct utmp pattern;
  struct utmp *utmp;

  trace("unix_process.c: do_utmp_cleanup\n");

  memset(&pattern, 0, sizeof(pattern));
  CP(pattern.ut_line, self->line);
  CP(pattern.ut_id, self->id);

  /* For Linux/glibc (and possibly others), we need to set 
   * ut_type to find our entry */

  pattern.ut_type = USER_PROCESS;

  /* Rewind database */
  setutent();
  utmp = getutid(&pattern);
  if (!utmp)
    /* Entry destroyed? Do nothing. */
    debug("unix_process.c: do_utmp_cleanup found no match\n");
  else
    {
      /* Make a working copy of this entry that we can modify */
      /* FIXME: Is this really needed??? /nisse */
      struct utmp wc = *utmp;
      utmp = &wc;

      utmp->ut_type = DEAD_PROCESS;

      debug("unix_process.c: do_utmp_cleanup getutid found match\n");

#if HAVE_STRUCT_UTMP_UT_EXIT
      utmp->ut_exit.e_exit = signaled ? 0 : value;
      utmp->ut_exit.e_termination = signaled ? value : 0;
#endif
      /* Clear ut_line, ut_host, ut_user and ut_tv */
      CLEAR(utmp->ut_line);
#if HAVE_STRUCT_UTMP_UT_HOST
      CLEAR(utmp->ut_host);
#endif
#if HAVE_STRUCT_UTMP_UT_USER
      CLEAR(utmp->ut_user);
#endif
#if HAVE_STRUCT_UTMP_UT_ADDR
      CLEAR(utmp->ut_addr);
#endif
#if HAVE_STRUCT_UTMP_UT_TV
      CLEAR(utmp->ut_tv);
#else
# if HAVE_STRUCT_UTMP_UT_TIME
      CLEAR(utmp->ut_time);
# endif
#endif
      
#if HAVE_PUTUTLINE
      if (!pututline(utmp))
	werror("Updating utmp for logout failed (errno = %i): %z\n",
	       errno, STRERROR(errno));
#endif
    }
#endif /* HAVE_UTMP_H */
#if HAVE_LOGWTMP
  logwtmp(lsh_get_cstring(self->line), "", "");
#endif
  EXIT_CALLBACK(self->c, signaled, core, value);
}

static struct utmp_cleanup *
make_utmp_cleanup(struct lsh_string *tty,
		  struct exit_callback *c)
{
  NEW(utmp_cleanup, self);
  UINT32 length = tty->length;
  UINT8 *data = tty->data;

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

#if HAVE_UTMP_H
  struct utmp pattern;
  struct utmp *utmp;
  
  trace("unix_process.c: utmp_book_keeping\n");

  memset(&pattern, 0, sizeof(pattern));
  CP(pattern.ut_line, cleanup->line);
  CP(pattern.ut_id, cleanup->id);

  /* FIXME: Initialize pattern.ut_type? */
  
  /* Rewind database */
  setutent();
  
  utmp = getutid(&pattern);
  if (utmp)
    /* Overwrite the line field, in case it was id that matched. */
    CP(utmp->ut_line, cleanup->line);
  else
    /* No existing entry, we need to create a new one. */
    utmp = &pattern;
  
  utmp->ut_type = USER_PROCESS;
  
#if HAVE_STRUCT_UTMP_UT_PID
  utmp->ut_pid = pid;
#endif

#if HAVE_STRUCT_UTMP_UT_USER
  CP(utmp->ut_user, name);
#endif

#if HAVE_STRUCT_UTMP_UT_TV
  gettimeofday(&utmp->ut_tv);
#else
# if HAVE_STRUCT_UTMP_UT_TIME
  time(&utmp->ut_time);
# endif
#endif
  
  trace("unix_process.c: utmp_book_keeping, after name\n");

  /* FIXME: We should store real values here. */
#if HAVE_STRUCT_UTMP_UT_ADDR
  CLEAR(utmp->ut_addr);
#endif
#if HAVE_STRUCT_UTMP_UT_ADDR_V6
  CLEAR(utmp->ut_addr_v6);
#endif
  
  /* FIXME: Perform a reverse lookup. */
#if HAVE_STRUCT_UTMP_UT_HOST
  CP(utmp->ut_host, peer->ip);
#endif
  trace("unix_process.c: utmp_book_keeping, after host\n");

#if HAVE_PUTUTLINE
  if (!pututline(utmp))
    werror("Updating utmp for login failed (errno = %i): %z\n",
	   errno, STRERROR(errno));
#endif

  trace("unix_process.c: utmp_book_keeping, after pututline\n");

#endif /* HAVE_UTMP_H */
  
#if HAVE_LOGWTMP
  logwtmp(lsh_get_cstring(cleanup->line),
	  lsh_get_cstring(name),
	  lsh_get_cstring(peer->ip));
#endif /* HAVE_LOGWTMP */

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
