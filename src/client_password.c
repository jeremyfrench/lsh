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

#include <stdarg.h>
#include <string.h>

#include <termios.h>

int echo_on(int fd)
{
  struct termios t;

  if (tcgetattr(fd, &t) < 0)
    {
      werror("Can't get terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  t->c_lflag |= ECHO;

  if (tcsetattr(fd, TCSANOW, &t) < 0)
    {
      werror("Can't set terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  return 1;
}

int echo_off(int fd)
{
  struct termios t;

  if (tcgetattr(fd, &t) < 0)
    {
      werror("Can't get terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  t->c_lflag &= ~ECHO;

  if (tcsetattr(fd, TCSAFLUSH, &t) < 0)
    {
      werror("Can't set terminal attributes: %s\n", strerror(errno));
      return 0;
    }

  return 1;
}

/* FIXME: Perhaps it is better to avoid using stdio functions? */
struct lsh_string *read_password(int max_length, char *format, ...)
{
  va_list args;
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

  va_start(args, format);
  vfprintf(tty, format, format, args);
  va_end(args);

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
