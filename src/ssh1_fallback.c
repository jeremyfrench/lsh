/* ssh1_fallback.h
 *
 * $Id$ */

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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "ssh1_fallback.h"

#include "werror.h"
#include "xalloc.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#define CLASS_DEFINE
#include "ssh1_fallback.h.x"
#undef CLASS_DEFINE

#include "ssh1_fallback.c.x"

/* CLASS:
   (class
     (name sshd1)
     (super ssh1_fallback)
     (vars
       ;; Full path to sshd1
       (sshd1 . "char *")))
*/

static int fall_back_to_ssh1(struct ssh1_fallback *c,
			     int fd, UINT32 length, const UINT8 *line)
{
  CAST(sshd1, closure, c);
  
  /* We fork a SSH1 server to handle this connection. */

  pid_t pid;
  pid = fork();
  if (pid < 0)
    {
      werror("Forking to start fallback sshd1 failed with %s\n",
	     strerror(errno));
      return LSH_FAIL | LSH_DIE;
    }
  else if (pid == 0)
    {
      /* Child process */

      /* Create a NUL-terminated version string. */
      char *version = alloca(length + 1);
      memcpy(version, line, length);
      version[length] = '\0';
      
      /* NOTE: All fds should have the close-on-exec flag set.
       * So all we have to do is to dup the socket fd to stdin
       * and stdout. */
	      
      /* FIXME: not implemented yet. How do we know the socket fd? */
      if (dup2(fd, STDIN_FILENO) < 0)
	{
	  werror("lshd: fall_back_to_ssh1: Failed to dup socket to STDIN.\n");
	  _exit(EXIT_FAILURE);
	}
      if (dup2(fd, STDOUT_FILENO) < 0)
	{
	  werror("lshd: fall_back_to_ssh1: Failed to dup socket to STDOUT.\n");
	  _exit(EXIT_FAILURE);
	}
      
      /* What should we do about stderr? We can probably not share it
       * (that would be more difficult if we had put it into
       * non-blocking mode, but we haven't). */

      execl(closure->sshd1, closure->sshd1,
	    "-i",			/* inetd mode */
	    "-V" ,version,	 	/* Compatibility mode */
	    NULL);
      werror("lshd: fall_back_to_ssh1: execl failed (errno = %d): %s\n",
	     errno, strerror(errno));
      _exit(EXIT_FAILURE);
    }
  else
    { /* pid > 0 */
      /* Parent */
      /* This tells the backend to close our socket. */
      return LSH_OK | LSH_DIE;
    }
}

struct ssh1_fallback *make_ssh1_fallback(char *sshd1)
{
  NEW(sshd1, closure);

  closure->super.fallback = fall_back_to_ssh1;
  closure->sshd1 = sshd1;

  return &closure->super;
}

