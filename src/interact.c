/* interact.c
 *
 * Interact with the user.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Niels Möller
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

#include "interact.h"

#include "io.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>

#define GABA_DEFINE
#include "interact.h.x"
#undef GABA_DEFINE

#if 0
int tty_fd = -1;

int lsh_open_tty(void)
{
#if HAVE_STDTTY_FILENO

  tty_fd = STDTTY_FILENO;
  return 1;

#else /* !HAVE_STDTTY_FILENO */

  int fd = open("/dev/tty", O_RDWR);
  if (fd < 0)
    return 0;
  tty_fd = fd;
  return 1;
  
#endif /* !HAVE_STDTTY_FILENO */
}

/* Depends on the tty being line buffered */
int tty_read_line(UINT32 size, UINT8 *buffer)
{
  UINT32 i = 0;

  while (i < size)
    {
      int res = read(tty_fd, buffer + i, size - i);
      if (!res)
	/* User pressed EOF (^D) */
	return i;
      else if (res < 0)
	switch(errno)
	  {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    /* I/O error */
	    werror("tty_read_line: %z (errno = %i)\n",
		   errno, STRERROR(errno));
	    return 0;
	  }
      else
	{
	  UINT32 j;
	  for (j = 0; j < (unsigned) res; j++, i++)
	    if (buffer[i] == '\n')
	      return i;
	}
    }
  /* We have filled our buffer already; continue reading until end of line */
#define BUFSIZE 512
  for (;;)
    {
      UINT8 b[BUFSIZE];
      int res = read(tty_fd, b, BUFSIZE);
      if (!res)
	/* EOF */
	return size;
      else if (res < 0)
	switch(errno)
	  {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    /* I/O error */
	    werror("tty_read_line: %z (errno = %i)\n",
		   errno, strerror(errno));
	    return 0;
	  }
      else
	{
	  UINT32 j;
	  for (j = 0; j < (unsigned) res; j++)
	    if (b[j] == '\n')
	      return res;
	}
    }
#undef BUFSIZE
}

#define TTY_BUFSIZE 10

int yes_or_no(struct lsh_string *s, int def, int free)
{
  UINT8 buffer[TTY_BUFSIZE];
  const struct exception *e;
  
  if ( (tty_fd < 0) || quiet_flag)
    {
      if (free)
	lsh_string_free(s);
      return def;
    }

  e = write_raw(tty_fd, s->length, s->data);

  if (free)
    lsh_string_free(s);

  if (e)
    return def;

  if (!tty_read_line(TTY_BUFSIZE, buffer))
    return def;

  switch (buffer[0])
    {
    case 'y':
    case 'Y':
      return 1;
    default:
      return 0;
    }
}
#endif  
