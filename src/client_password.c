/* client_password.c
 *
 * System dependant password related functions.
 */

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

#include "password.h"

#include "format.h"
#include "xalloc.h"
#include "werror.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <termios.h>
#include <pwd.h>

struct lsh_string *read_password(int max_length,
				 struct lsh_string *prompt, int free)
{
  /* NOTE: Ignores max_length; instead getpass()'s limit applies. */

  char *password;
  
  prompt = make_cstring(prompt, free);

  if (!prompt)
    return 0;

  /* NOTE: This function uses a static buffer. */
  password = getpass(prompt->data);

  lsh_string_free(prompt);
  
  if (!password)
    return 0;

  return format_cstring(password);
}

#if 0
static int echo_on(int fd)
{
  struct termios t;

  if (tcgetattr(fd, &t) < 0)
    {
      werror("Can't get terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  t.c_lflag |= ECHO;

  if (tcsetattr(fd, TCSANOW, &t) < 0)
    {
      werror("Can't set terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  return 1;
}

static int echo_off(int fd)
{
  struct termios t;

  if (tcgetattr(fd, &t) < 0)
    {
      werror("Can't get terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  t.c_lflag &= ~ECHO;

  if (tcsetattr(fd, TCSAFLUSH, &t) < 0)
    {
      werror("Can't set terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  return 1;
}

/* FIXME: Perhaps it is better to avoid using stdio functions? */
struct lsh_string *read_password(int max_length, struct lsh_string *prompt)
{
  int fd;
  FILE *tty;

  struct lsh_string *res;
  
  fd = open("/dev/tty", O_RDWR);

  if (fd < 0)
    {
      werror("Can't open /dev/tty: %s\n", strerror(errno));
      return 0;
    }
  tty = fdopen(fd, "rw");
  if (!tty)
    {
      close(fd);
      werror("Can't fdopen /dev/tty: %s\n", strerror(errno));
      return 0;
    }

  /* Ignore errors */
  (void) echo_off(fd);

  fwrite(prompt->data, 1, prompt->length, tty);

  fflush(tty);

  res = lsh_string_alloc(max_length);
  if (!fgets(res->data, max_length, tty))
    res = 0;
  else
    {
      res->length = strlen(res->data);
      /* Delete terminating newline */
      if (res->length && (res->data[res->length-1] == '\n'))
	res->length--;
    }

  /* Ignore errors */
  (void) echo_on(fd);
	  
  fclose(tty);

  return res;
}
#endif
