/* tty.h
 *
 * $Id$ */

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

#include "tty.h"
#include "werror.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>


int tty_getattr(int fd, struct termios *ios)
{
  return tcgetattr(fd, ios) != -1 ? 1 : 0;
}

int tty_setattr(int fd, struct termios *ios)
{
  return tcsetattr(fd, TCSADRAIN, ios) != -1 ? 1 : 0;
}

/* NOTE: This function also makes the current process a process group
 * leader. */
int tty_setctty(int newtty)
{
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
  if (setsid() < 0)
    werror("pty_setctty: setsid() failed, already process group leader?\n"
	   "   (errno = %d): %s\n", errno, strerror(errno));
  
  if (ioctl(newtty, TIOCSCTTY, NULL) == -1)
    {
      werror("pty_setctty: Failed to set the controlling tty\n");
      return 0;
    }
  
  return 1;
}

int tty_makeraw(int fd)
{
  struct termios ios;
	
  if (tty_getattr(fd, &ios))
    {
      cfmakeraw(&ios);
      return tty_setattr(fd, &ios);
    }
  return 0;
}

int tty_getwinsize(int fd, int *w, int *h, int *wp, int *hp)
{
  struct winsize ws;
  int rc;
  
  rc = ioctl(fd, TIOCGWINSZ, &ws);
  if (rc != -1)
    {
      *w = ws.ws_col;
      *h = ws.ws_row;
      *wp = ws.ws_xpixel;
      *hp = ws.ws_ypixel;
      return 1;
    }
  return 0;
}

int tty_setwinsize(int fd, int w, int h, int wp, int hp)
{
  struct winsize ws;
  
  ws.ws_row = h;
  ws.ws_col = w;
  ws.ws_xpixel = wp;
  ws.ws_ypixel = hp;
  
  return ioctl(fd, TIOCSWINSZ, &ws) == -1 ? 0 : 1;
}
