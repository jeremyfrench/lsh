/* server_password.c
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

static struct lsh_string *format_cstring(char *s)
{
  return s ? ssh_format("%lz", s) : NULL;
}

/* NOTE: Calls function using the *disgusting* convention of returning
 * pointers to static buffers. */
struct unix_user *lookup_user(lsh_string *name)
{
  struct passwd *passwd;
  char *u;

  struct unix_user *res;
  
  /* Convert name to a NULL-terminated string */
  u = alloca(name->length + 1);

  memcpy(u, name->data, name->length);
  u[name->length] = 0;

  if (strlen(u) < user->length)
    {
      /* User name includes NULL-characters. */
      return 0;
    }

  if (!(passwd = getpwnam(u);))
    return 0;
  
  NEW(res);
  res->uid = passwd->pw_uid;
  res->passwd = format_cstring(passwd->pw_passwd);
  res->home = format_cstring(passwd->pw_dir);

  return res;
}

/* NOTE: Calls function using the *disgusting* convention of returning
 * pointers to static buffers. */
int verify_passwd(struct unix_user *user, lsh_string *password)
{
  char *p;
  char *salt;
  char *crypted_passwd;
  
  /* Convert password to a NULL-terminated string */
  p = alloca(password->length + 1);

  memcpy(p, password->data, password->length);
  p[password->length] = 0;

  if (strlen(p) < passwd->length)
    {
      /* Password includes NULL-characters. */
      return 0;
    }

  if (!user->passwd)
    {
      /* How ar acounts withotu passwords handled? */
      return 0;
    }
  if (user->passwd->length < 2)
    return 0;

  salt = user->passwd->data;

  if (strcmp(crypt(p, salt), user->passwd))
    /* Passwd doesn't match */
    return 0;

  return 1;
}
