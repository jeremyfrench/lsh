/* server_pty.h
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, Niels Möller, Balazs Scheidler
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "server_pty.h"

#include "channel.h"
#include "connection.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>  /* FIXME: for snprintf, maybe use a custom snprintf? Bazsi */

#if HAVE_STROPTS_H
#  include <stropts.h>  /* isastream() */
#endif

#if HAVE_PTY_H
#  include <pty.h>  /* openpty() */
#endif


#define GABA_DEFINE
#include "server_pty.h.x"
#undef GABA_DEFINE

static void do_kill_pty_info(struct resource *r)
{
  CAST(pty_info, closure, r);

  if (closure->super.alive)
    {
      closure->super.alive = 0;
      if (close(closure->master) < 0)
	werror("do_kill_pty_info: closing master failed (errno = %i): %z\n",
	       errno, strerror(errno));
      if (close(closure->slave) < 0)
	werror("do_kill_pty_info: closing slave failed (errno = %i): %z\n",
	       errno, strerror(errno));
    }
}

struct pty_info *make_pty_info(void)
{
  NEW(pty_info, pty);

  pty->super.alive = 0;
  pty->super.kill = do_kill_pty_info;

  /* pty->tty_name = NULL; */ /* Cleared by NEW() */
  return pty;
}

int pty_allocate(struct pty_info *pty)
{
#if UNIX98_PTYS
  char *name;
  if ((pty->master = open("/dev/ptmx", O_RDWR | O_NOCTTY)) < 0)
    {
      return 0;
    }

  /* FIXME: Calling grantpt now will set wrong permissions on the tty,
   * as this function is called before the server forks and changes
   * uid. */
  if (grantpt(pty->master) < 0 || unlockpt(pty->master) < 0)
    goto close_master;
  name = ptsname(pty->master);
  if (name == NULL)
    goto close_master;

  pty->slave = open(name, O_RDWR | O_NOCTTY);
  if (pty->slave == -1)
    goto close_master;

# ifdef HAVE_STROPTS_H
  if (isastream(pty->slave))
    {
      if (ioctl(pty->slave, I_PUSH, "ptem") < 0
          || ioctl(pty->slave, I_PUSH, "ldterm") < 0)
        goto close_slave;
    }
#  endif /* HAVE_STROPTS_H */

  pty->tty_name = format_cstring(name);
  return 1;

close_slave:
  close (pty->slave);

close_master:
  close (pty->master);
  return 0;

#elif HAVE_OPENPTY

  return openpty(&pty->master, &pty->slave, NULL, NULL, NULL) == 0 ?
         1 : 0;

#elif PTY_BSD_SCHEME

#define PTY_BSD_SCHEME_MASTER "/dev/pty%c%c"
#define PTY_BSD_SCHEME_SLAVE  "/dev/tty%c%c"
  char first[] = PTY_BSD_SCHEME_FIRST_CHARS;
  char second[] = PTY_BSD_SCHEME_SECOND_CHARS;
  char master[MAX_TTY_NAME], slave[MAX_TTY_NAME];
  unsigned int i, j;
  int saved_errno;

  for (i = 0; i < sizeof(first); i++)
    {
      for (j = 0; j < sizeof(second); j++) 
        {
	  snprintf(master, sizeof(master),
		   PTY_BSD_SCHEME_MASTER, first[i], second[j]);
			
	  pty->master = open(master, O_RDWR | O_NOCTTY);
	  if (pty->master != -1) 
	    {
	      /* master succesfully opened */
	      snprintf(slave, sizeof(slave),
		       PTY_BSD_SCHEME_SLAVE, first[i], second[j]);
				
	      pty->slave = open(slave, O_RDWR | O_NOCTTY);
	      if (pty->slave == -1) 
	        {
		  saved_errno = errno;
		  close(pty->master);
		  pty->master = -1;
		  errno = saved_errno;
		  return 0;
	        }
	      pty->tty_name = format_cstring(slave);
              return 1;
	    }
        }
    }
  return 0;
#else /* !PTY_BSD_SCHEME */
  /* No pty:s */
  return 0;
#endif
}

/* NOTE: This function also makes the current process a process group
 * leader. */
int tty_setctty(struct pty_info *pty)
{
  debug("tty_setctty\n");
  if (setsid() < 0)
    {
      werror("tty_setctty: setsid() failed, already process group leader?\n"
	     "   (errno = %i): %z\n", errno, strerror(errno));
      return 0;
    }
#if HAVE_UNIX98_PTYS
  {
    int fd;

    /* FIXME: For some reason, it doesn't work to call grantpt() again
     * here. Hopefully, there is some other way to do things right. */
#if 0
    /* Set up permissions with our new uid. */
    if (grantpt(pty->master) < 0)
      {
	werror("tty_setctty: grantpt() failed,\n"
	       "   (errno = %i): %z\n", errno, strerror(errno));
	return 0;
      }
    if (unlockpt(pty->master) < 0)
      {
	werror("tty_setctty: unlockpt() failed,\n"
	       "   (errno = %i): %z\n", errno, strerror(errno));
	return 0;
      }
#endif
    
    /* Open the slave, to make it our controlling tty */
    /* FIXME: According to carson@tla.org, there's a cleaner POSIX way
     * to make a tty the process's controlling tty. */
    debug("setctty: Attempting open\n");
    fd = open(pty->tty_name->data, O_RDWR);
    if (fd < 0)
      {
	werror("tty_setctty: open(\"%z\") failed,\n"
	       "   (errno = %i): %z\n",
	       pty->tty_name->data, errno, strerror(errno));
	return 0;
      }
    close(fd);

    return 1;
  }
#elif PTY_BSD_SCHEME
  {
    /* Is this really needed? setsid() should unregister the
     * controlling tty */
#if 0
    int oldtty;
  
    oldtty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (oldtty >= 0)
      {
	ioctl(oldtty, TIOCNOTTY, NULL);
	close(oldtty);
	oldtty = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (oldtty >= 0)
	  {
	    werror("pty_setctty: Error disconnecting from controlling tty.\n");
	    close(oldtty);
	    return 0;
	  }
      }
#endif
    
    if (ioctl(pty->slave, TIOCSCTTY, NULL) == -1)
      {
	werror("tty_setctty: Failed to set the controlling tty.\n"
	       "   (errno = %i): %z\n", errno, strerror(errno));
	return 0;
      }
    
    return 1;
  }
#else /* !PTY_BSD_SCHEME */
#error Dont know how to register a controlling tty
#endif
}
