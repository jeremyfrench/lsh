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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "server_pty.h"
#include "xalloc.h"

#include "parse.h"
#include "connection.h"
#include "channel.h"
#include "werror.h"

#include "ssh.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>  /* FIXME: for snprintf, maybe use a custom snprintf? Bazsi */

#define CLASS_DEFINE
#include "server_pty.h.x"
#undef CLASS_DEFINE

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

  return pty;
}

#if HAVE_OPENPTY

int pty_allocate(struct pty_info *pty)
{
  return openpty(&pty->fd_master, &pty->fd_slave, NULL, NULL, NULL) == 0 ?
         1 : 0;
}

#elif PTY_BSD_SCHEME

#define PTY_BSD_SCHEME_MASTER "/dev/pty%c%c"
#define PTY_BSD_SCHEME_SLAVE  "/dev/tty%c%c"

int pty_allocate(struct pty_info *pty)
{
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
	      
              return 1;
	    }
        }
    }
  return 0;
}

#endif
