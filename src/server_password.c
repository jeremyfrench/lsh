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
#include "format.h"
#include "parse.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>
#include <errno.h>

#include <pwd.h>
#include <grp.h>

/* These functions add an extra NUL-character at the end of the string
 * (not included in the length), to make it possible to pass the
 * string directly to C library functions. */

static struct lsh_string *format_cstring(char *s)
{
  if (s)
    {
      struct lsh_string *res = ssh_format("%lz%c", s, 0);
      res->length--;
      return res;
    }
  return NULL; 
}

static struct lsh_string *make_cstring(struct lsh_string *s, int free)
{
  struct lsh_string *res;
  
  if (memchr(s->data, '\0', s->length))
    {
      if (free)
	lsh_string_free(s);
      return 0;
    }

  res = ssh_format("%lS%c", s, 0);
  res->length--;
  
  if (free)
    lsh_string_free(s);
  return res;
}
    
/* NOTE: Calls functions using the *disgusting* convention of returning
 * pointers to static buffers. */
struct unix_user *lookup_user(struct lsh_string *name, int free)
{
  struct passwd *passwd;
  struct unix_user *res;

  name = make_cstring(name, free);

  if (!name)
    return 0;
  
  if (!(passwd = getpwnam(name->data)))
    return 0;
  
  NEW(res);
  res->uid = passwd->pw_uid;
  res->gid = passwd->pw_gid;
  res->name = name;
  res->passwd = format_cstring(passwd->pw_passwd);
  res->home = format_cstring(passwd->pw_dir);
  res->shell = format_cstring(passwd->pw_shell);
  
  return res;
}

/* NOTE: Calls functions using the *disgusting* convention of returning
 * pointers to static buffers. */
int verify_password(struct unix_user *user,
		    struct lsh_string *password, int free)
{
  char *salt;
  
  /* Convert password to a NULL-terminated string */
  password = make_cstring(password, free);

  if (!user->passwd || (user->passwd->length < 2) )
    {
      /* FIXME: How are accounts without passwords handled? */
      lsh_string_free(password);
      return 0;
    }

  salt = user->passwd->data;

  if (strcmp(crypt(password->data, salt), user->passwd->data))
    {
      /* Passwd doesn't match */
      lsh_string_free(password);
      return 0;
    }

  lsh_string_free(password);
  return 1;
}

struct unix_authentication
{
  struct userauth super;

#if 0
  struct login_method *login;
#endif
  /* Services allowed. Maps names to struct unix_service */
  struct alist *services; 
};

static int do_authenticate(struct userauth *c,
			   struct lsh_string *username,
			   int requested_service,
			   struct simple_buffer *args,
			   struct ssh_service **result)
{
  struct unix_authentication *closure = (struct unix_authentication *) c;
  struct lsh_string *password = NULL;
  struct unix_service *service;
  int change_passwd;
  
  MDEBUG(closure);

  if (!( (service = ALIST_GET(closure->services, requested_service))))
    {
      lsh_string_free(username);
      return LSH_AUTH_FAILED;
    }

  username = utf8_to_local(username, 1);
  if (!username)
    return 0;

  if (parse_boolean(args, &change_passwd))
    {
      if (change_passwd)
	{
	  /* Password changeing is not implemented. */
	  lsh_string_free(username);
	  return LSH_AUTH_FAILED;
	}
      if ( (password = parse_string_copy(args))
	   && parse_eod(args))
	{
	  struct unix_user *user;
	  int access;

	  password = utf8_to_local(password, 1);

	  if (!password)
	    {
	      lsh_string_free(username);
	      return LSH_AUTH_FAILED;
	    }
       
	  user = lookup_user(username, 1);

	  if (!user)
	    {
	      lsh_string_free(password);
	      return LSH_AUTH_FAILED;
	    }

	  access = verify_password(user, password, 1);

	  if (access)
	    {
	      *result = LOGIN(service, user);
	      return LSH_OK | LSH_GOON;
	    }
	  else
	    {
	      /* FIXME: Free user struct */
	      return LSH_AUTH_FAILED;
	    }
	}
    }

  /* Request was invalid */
  lsh_string_free(username);

  if (password)
    lsh_string_free(password);
  return LSH_FAIL | LSH_DIE;
}
  
struct userauth *make_unix_userauth(struct alist *services)
{
  struct unix_authentication *closure;

  NEW(closure);
  closure->super.authenticate = do_authenticate;
#if 0
  closure->login = login;
#endif
  closure->services = services;

  return &closure->super;
}

int change_uid(struct unix_user *user)
{
  /* NOTE: Error handling is crucial here. If we do something
   * wrong, the server will think that the user is logged in
   * under his or her user id, while in fact the process is
   * still running as root. */
  if (initgroups(user->name->data, user->gid) < 0)
    {
      werror("initgroups failed: %s\n", strerror(errno));
      return 0;
    }
  if (setgid(user->gid) < 0)
    {
      werror("setgid failed: %s\n", strerror(errno));
      return 0;
    }
  if (setuid(user->uid) < 0)
    {
      werror("setuid failed: %s\n", strerror(errno));
      return 0;
    }
  return 1;
}

int change_dir(struct unix_user *user)
{
  /* Change to user's home directory. FIXME: If the server is running
   * as the same user, perhaps it's better to use $HOME? */
  if (!user->home)
    {
      if (chdir("/") < 0)
	{
	  werror("Strange: home directory was NULL, and chdir(\"/\") failed: %s\n",
		 strerror(errno));
	  return 0;
	}
    }
  else if (chdir(user->home->data) < 0)
    {
      werror("chdir to %s failed (using / instead): %s\n",
	     user->home ? (char *) user->home->data : "none",
	     strerror(errno));
      if (chdir("/") < 0)
	{
	  werror("chdir(\"/\") failed: %s\n", strerror(errno));
	  return 0;
	}
    }
  return 1;  
}

struct setuid_service
{
  struct ssh_service super;

  struct unix_user *user;
  /* Service to start once we have changed to the correct uid. */
  struct ssh_service *service;
};

#if 0

/* NOTE: This is used only if early forking (i.e., for directly after
 * user autentication) is enabled. */
static int do_setuid(struct ssh_service *c,
		     struct ssh_connection *connection)
{
  struct setuid_service *closure  = (struct setuid_service *) c;  
  uid_t server_uid = getuid();
  int res = 0;

  MDEBUG(closure);
  
  if (server_uid != closure->user->uid)
    {
      if (server_uid)
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

	  if (!change_uid(closure->user))
	    return  LSH_FAIL | LSH_DIE | LSH_KILL_OTHERS;;

	  res |= LSH_KILL_OTHERS;
	  break;
	default:
	  /* Parent */
	  return LSH_OK | LSH_DIE;
	}
    }

  /* Change to user's home directory. FIXME: If the server is running
   * as the same user, perhaps it's better to use $HOME? */
  if (!change_dir(closure->user))
    fatal("can't chdir: giving up\n");

  /* Initialize environment, somehow. In particular, the HOME and
   * LOGNAME variables */

  return res | LOGIN(closure->service, closure->user);		     connection);
}

/* FIXME: This function is not quite adequate, as it does not pass the
 * user struct on to the started service. */

static struct ssh_service *do_login(struct login_method *closure,
				    struct unix_user *user,
				    struct ssh_service *service)
{
  struct setuid_service *res;

  MDEBUG(closure);
  
  NEW(res);
  res->super.init = do_setuid;
  res->user = user;
  res->service = service;

  return &res->super;
}

struct login_method *make_unix_login(void)
{
  struct login_method *self;

  NEW(self);
  self->login = do_login;

  return self;
}
#endif
