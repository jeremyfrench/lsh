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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "charset.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "server_userauth.h"
#include "werror.h"
#include "xalloc.h"

static void
do_authenticate(struct userauth *ignored UNUSED,
		struct ssh_connection *connection UNUSED,
		struct lsh_string *username,
		UINT32 service UNUSED,
		struct simple_buffer *args,
		struct command_continuation *c,
		struct exception_handler *e)
{
  struct lsh_string *password = NULL;
  /* struct unix_service *service; */
  int change_passwd;
  
  username = utf8_to_local(username, 1, 1);
  if (!username)
    {
      PROTOCOL_ERROR(e, "Invalid utf8 in password.");
      return;
    }

  if (parse_boolean(args, &change_passwd))
    {
      if (change_passwd)
	{
	  static const struct exception passwd_change_not_implemented
	    = STATIC_EXCEPTION(EXC_USERAUTH,
			       "Password change not implemented.");
	  
	  lsh_string_free(username);
	  EXCEPTION_RAISE(e, &passwd_change_not_implemented);
			  
	  return;
	}
      if ( (password = parse_string_copy(args))
	   && parse_eod(args))
	{
	  struct unix_user *user;

	  password = utf8_to_local(password, 1, 1);

	  if (!password)
	    {
	      lsh_string_free(username);
	      PROTOCOL_ERROR(e, "Invalid utf8 in password.");
	      return;
	    }
       
	  user = lookup_user(username, 1);

	  if (!user)
	    {
	      static const struct exception no_such_user
		= STATIC_EXCEPTION(EXC_USERAUTH, "No such user");
	      
	      lsh_string_free(password);
	      EXCEPTION_RAISE(e, &no_such_user);
	      return;
	    }

	  if (verify_password(user, password, 1))
	    {
	      COMMAND_RETURN(c, user);
	      return;
	    }
	  else
	    {
	      static const struct exception bad_passwd
		= STATIC_EXCEPTION(EXC_USERAUTH, "Wrong password");

	      KILL(user);
	      EXCEPTION_RAISE(e, &bad_passwd);
	      return;
	    }
	}
    }
  
  /* Request was invalid */
  lsh_string_free(username);

  if (password)
    lsh_string_free(password);

  PROTOCOL_ERROR(e, "Invalid password USERAUTH message.");
}

struct userauth unix_userauth =
{ STATIC_HEADER, do_authenticate };

#if 0

struct setuid_service
{
  struct ssh_service super;

  struct unix_user *user;
  /* Service to start once we have changed to the correct uid. */
  struct ssh_service *service;
};

/* NOTE: This is used only if early forking (i.e., for directly after
 * user autentication) is enabled. */
static int do_setuid(struct ssh_service *c,
		     struct ssh_connection *connection)
{
  CAST(setuid_service, closure, c);  
  uid_t server_uid = getuid();
  int res = 0;

  if (server_uid != closure->user->uid)
    {
      if (server_uid)
	/* Not root */
	return LSH_AUTH_FAILED;

      switch(fork())
	{
	case -1:
	  /* Error */
	  werror("fork failed: %z\n", STRERROR(errno));
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
