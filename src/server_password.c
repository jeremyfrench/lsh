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

#include "charset.h"
#include "parse.h"
#include "xalloc.h"

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
#if 0
  res->username = ssh_format("%lz", passwd->name);
#endif
  res->passwd = format_cstring(passwd->pw_passwd);
  res->home = format_cstring(passwd->pw_dir);

  return res;
}

/* NOTE: Calls function using the *disgusting* convention of returning
 * pointers to static buffers. */
int verify_password(struct unix_user *user,
		    struct lsh_string *password)
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
      /* How are accounts without passwords handled? */
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

struct unix_authentication
{
  struct userauth super;

  struct alist *services;  /* Services allowed */
};

static int do_authenticate(struct userauth *c,
			   struct lsh_string *username,
			   int requested_service,
			   struct simple_buffer *args,
			   struct ssh_service **service)
{
  struct unix_authentication *closure = (struct unix_authentication *) c;
  struct lsh_string * password = NULL;

  struct unix_service *login;

  MDEBUG(closure);

  if (!( (login = ALIST_GET(closure->services, requested_service))))
    {
      lsh_string_free(user);
      return LSH_AUTH_FAILED;
    }

  username = utf8_to_local(username, 1);
  if (!username)
    return 0;
  
  if (parse_string_copy(&buffer, &password)
      && parse_eod(&buffer))
    {
      struct unix_user *user;
      int access;

      password = utf8_to_local(password, 1);

      if (!password)
	{
	  lsh_string_free(username);
	  return LSH_AUTH_FAILED;
	}
       
      user = lookup_user(user_length, username);
      lsh_string_free(user);

      if (!user)
	{
	  lsh_string_free(password);
	  return LSH_AUTH_FAILED;
	}

      access = verify_password(user, password);

      lsh_string_free(password);

      if (access)
	return LOGIN(login, user);
      else
	{
	  lsh_free(user);
	  return LSH_AUTH_FAILED;
	}
    }
  lsh_string_free(user);

  if (password)
    lsh_string_free(password);
  return 0;
}
  
struct userauth *make_unix_userauth(struct alist *services)
{
  struct unix_authentication *closure;

  NEW(closure);
  closure->super.authenticate = do_authenticate;
  closure->services = services;

  return &closure->super;
}

struct setuid_handler
{
  struct unix_service super;

  /* Service to start once we have changed to the correct uid. */
  struct ssh_service *service;
};

static int do_setuid(struct unix_service *closure, struct user)
{
  uid_t servers_uid = get_uid();
  int res = 0;
  struct *pw;

  pw = getpwuid(user->uid);
  if (!pw)
    {
      werror("do_fork: User disappeared!\n");
      return LSH_AUTH_FAILED;
    }

  if (servers_uid != user->uid)
    {
      if (servers_uid)
	/* Not root */
	return LSH_AUTH_FAILED;

      switch(fork())
	{
	case -1:
	  /* Error */
	  werror("fork failed: %s\n", strerror(errno));
	  return LSH_FAIL | LSH_DIE;
	case 0:
	  /* Child */
	  
	  /* NOTE: Error handling is crucial here. If we do something
	   * wrong, the server will think that the user is logged in
	   * under his or her user id, while in fact the process is
	   * still running as root. */
	  if (initgroups(pw->pw_name, pw->pw_gid) < 0)
	    {
	      werror("initgroups failed: %s\n", strerror(errno));
	      return LSH_FAIL | LSH_DIE | LSH_KILL_OTHERS;
	    }
	  if (setgid(pw->pw_gid) < 0)
	    {
	      werror("setgid failed: %s\n", strerror(errno));
	      return LSH_FAIL | LSH_DIE | LSH_KILL_OTHERS;
	    }
	  if (setuid(pw->pw_uid) < 0)
	    {
	      werror("setuid failed: %s\n", strerror(errno));
	      return LSH_FAIL | LSH_DIE | LSH_KILL_OTHERS;
	    }
	  
	  res |= LSH_KILL_OTHERS;
	  break;
	default:
	  /* Parent */
	  return LSH_OK | LSH_DIE;
	}
    }

  /* Change to user's home directory. FIXME: If the server is running
   * as the same user, perhaps it's better to use $HOME? */
  if (!pw->pw_dir)
    {
      if (chdir("/") < 0)
	fatal("Strange: pw->pw_dir is NULL, and chdir(\"/\") failed: %s\n",
	      strerror(errno));
    }
  else
    if (chdir(pw->pw_dir) < 0)
      {
	werror("chdir to %s failed (using / instead): %s\n",
	       pw->pw_dir ? pw->pw_dir : "none", strerror(errno));
	if (chdir("/") < 0)
	  fatal("chdir(\"/\") failed: %s\n", strerror(errno));
      }
  	       
  /* Initialize the service, somehow */
}

struct unix_service *make_setuid_handler(struct ssh_service *service)
{
  struct setuid_handler *closure;

  NEW(closure);

  closure->super.login = do_setuid;
  closure->service = service;

  return &closure->super;
}
