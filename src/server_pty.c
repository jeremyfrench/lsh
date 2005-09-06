/* server_pty.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>

#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#if HAVE_STROPTS_H
# include <stropts.h>  /* isastream() */
#endif

#include "server_pty.h"

#include "channel.h"
#include "format.h"
#include "lsh_string.h"
#include "parse.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"


#define GABA_DEFINE
#include "server_pty.h.x"
#undef GABA_DEFINE

static void
do_kill_pty_info(struct resource *r)
{
  CAST(pty_info, pty, r);

  if (pty->super.alive)
    {
      pty->super.alive = 0;
      if ( (pty->master >= 0) && (close(pty->master) < 0) )
	werror("do_kill_pty_info: closing master failed %e\n", errno);
    }
}

struct pty_info *
make_pty_info(void)
{
  NEW(pty_info, pty);

  init_resource(&pty->super, do_kill_pty_info);
  pty->tty_name = NULL;
  pty->mode = NULL;
  pty->master = -1;
  return pty;
}

int
pty_open_master(struct pty_info *pty)
{
#if HAVE_UNIX98_PTYS
  if ((pty->master = open("/dev/ptmx", O_RDWR | O_NOCTTY)) < 0)
    {
      werror("pty_open_master: Opening /dev/ptmx failed %e\n", errno);
      return 0;
    }
  
  if ((grantpt(pty->master) == 0)
      && (unlockpt(pty->master) == 0))
    {
      pty->tty_name = make_string(ptsname(pty->master));
      return 1;
    }

  close (pty->master); pty->master = -1;
#endif

  /* FIXME: We can't set up correct permissions since we're not root.
     We need some trick like pty-creation deamon. */
  return 0;
}

/* Opens the slave side of the tty, intitializes it, and makes it our
 * controlling terminal. Should be called by the child process.
 *
 * Also makes the current process a session leader.
 *
 * Returns an fd, or -1 on error. */
int
pty_open_slave(struct pty_info *pty)
{
  struct termios ios;
  int fd;
  
  trace("pty_open_slave\n");

  /* Open the slave. On Sys V, that also makes it our controlling tty. */
  fd = open(lsh_get_cstring(pty->tty_name), O_RDWR);

  if (fd < 0)
    {
      werror("pty_open_slave: open(\"%S\") failed,\n"
	     "   %e\n",
	     pty->tty_name, errno);
      return -1;
    }

  /* For Sys V and Solaris, push some streams modules.
   * This seems to also have the side effect of making the
   * tty become our controlling terminal. */
# ifdef HAVE_STROPTS_H
  if (isastream(fd))
    {
      if (ioctl(fd, I_PUSH, "ptem") < 0)
	{
	  werror("pty_open_slave: Failed to push streams module `ptem'.\n"
		 "   %e\n", errno);
	
	  close(fd);
	  return -1;
	}
      if (ioctl(fd, I_PUSH, "ldterm") < 0)
	{
	  werror("pty_open_slave: Failed to push streams module `ldterm'.\n"
		 "   %e\n", errno);
	
	  close(fd);
	  return -1;
	}
    }
# endif /* HAVE_STROPTS_H */

  /* On BSD systems, use TIOCSCTTY. */

#ifdef TIOCSCTTY
  if (ioctl(fd, TIOCSCTTY, NULL) < 0)
    {
      werror("pty_open_slave: Failed to set the controlling tty.\n"
	     "   %e\n", errno);
      close(fd);
      return -1;
    }
#endif /* defined(TIOCSCTTY) */

  /* Set terminal modes */
  if (!tty_getattr(fd, &ios))
    {
      werror("pty_open_slave: Failed to get tty attributes.\n"
	     "   %e\n", errno);
      close(fd);
      return -1;
    }

  if (!tty_decode_term_mode(&ios, STRING_LD(pty->mode)))
    {
      werror("pty_open_slave: Invalid terminal modes from client.\n");
      close(fd);
      return -1;
    }

  if (!tty_setattr(fd, &ios))
    {
      werror("pty_open_slave: Failed to set tty attributes.\n"
	     "   %e\n", errno);
      close(fd);
      return -1;
    }
	  
  if (!tty_setwinsize(fd, &pty->dims))
    {
      werror("pty_open_slave: Failed to set tty window size.\n"
	     "   %e\n", errno);
      close(fd);
      return -1;
    }

  return fd;
}
