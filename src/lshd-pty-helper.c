/* lshd-pty-helper.c
 *
 * Helper program for managing pty:s. An unprivileged process
 * communicates with this program via a AF_UNIX socket. Either a named
 * socket, or socket pair(s) provided as stdin and stdout.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2006 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <grp.h>
#include <utmpx.h>

#include "environ.h"
#include "pty-helper.h"

#ifndef GROUP_TTY
#define GROUP_TTY "tty"
#endif

#ifndef GROUP_SYSTEM
#define GROUP_SYSTEM "system"
#endif

/* Includes user, group and other bits, as well as the suid, sgid and
   sticky bit. */
#ifndef ACCESS_MASK
#define ACCESS_MASK 07777
#endif

/* Desired tty access bits (rw--w----). Can we gain any portability by
   writing S_IRUSR | S_IWUSR | S_IWGRP ? */
#ifndef ACCESS_TTY
#define ACCESS_TTY 0620
#endif

static const char *wtmp_file;

static void
die(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
     __attribute__((__noreturn__))
#endif
     ;

static void
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

static void
werror(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
#endif
     ;

static void
werror(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

/* The state associated with a pty and an utmp entry. */
struct pty_object
{
  char free;

  /* Non-zero if we have an utmp entry to clean up. */
  char active;
  
  /* The client's uid. */
  uid_t uid;

  /* Name of slave tty */
  const char *tty;

  struct utmpx entry;
};

struct pty_state
{
  /* Group that should own the slave tty. */
  gid_t tty_gid;

  /* Expected user id, or -1 if unset. */
  uid_t uid;

  unsigned nobjects;
  struct pty_object *objects;
};

static void
init_pty_state(struct pty_state *state, uid_t uid)
{
  struct group *grp;

  /* Points to static area */
  grp = getgrnam(GROUP_TTY);

  if (!grp)
    /* On AIX, tty:s have group "system", not "tty" */
    grp = getgrnam(GROUP_SYSTEM);

  state->tty_gid = grp ? grp->gr_gid : (gid_t) -1;

  state->uid = uid;

  state->nobjects = 0;
  state->objects = NULL;
}

static struct pty_object *
pty_object_alloc(struct pty_state *state, unsigned *index)
{
  struct pty_object *pty = NULL;
  unsigned i;
  
  for (i = 0; i < state->nobjects; i++)
    if (state->objects[i].free)
      {
	*index = i;
	pty = state->objects + i;
	break;
      }

  if (!pty)
    {
      /* Try reallocating */
      size_t n = 2*state->nobjects + 10;
      void *p = realloc(state->objects, n*sizeof(*state->objects));

      if (!p)
	return NULL;

      state->objects = p;
      
      *index = state->nobjects;
      pty = state->objects + state->nobjects;

      for (i = state->nobjects; i < n; i++)
	state->objects[i].free = 1;

      state->nobjects = n;
    }

  memset(pty, 0, sizeof(*pty));

  return pty;
}

static void
pty_object_free(struct pty_state *state, unsigned index)
{
  assert(index < state->nobjects);
  assert(!state->objects[index].free);
  
  free((void *) state->objects[index].tty);
  
  state->objects[index].free = 1;
}

/* Sets the permissions on the slave pty suitably for use by USER.
 * This function is derived from the grantpt function in
 * sysdeps/unix/grantpt.c in glibc-2.1. */

/* Returns errno value on error */
static int
pty_set_permissions(const char *name, uid_t uid, gid_t gid)
{
  struct stat st;

  if (stat(name, &st) < 0)
    return errno;

  /* Make sure that the user owns the device. */
  if (st.st_uid == uid)
    uid = -1;
  if (st.st_gid == gid)
    gid = -1;

  if (uid != (uid_t) -1 || gid != (gid_t) -1)
    if (chown(name, uid, gid) < 0)
      return errno;

  /* Make sure the permission mode is set to readable and writable
   * by the owner, and writable by the group. */

  if ( (st.st_mode & ACCESS_MASK) != ACCESS_TTY
       && chmod(name, ACCESS_TTY) < 0)
    return errno;

  /* Everything is fine */
  return 0;
}

static int
strprefix_p(const char *prefix, const char *s)
{
  unsigned i;

  for (i = 0; prefix[i]; i++)
    if (prefix[i] != s[i])
      return 0;
  return 1;
}

#define CP(dst, src) (strncpy((dst), (src), sizeof(dst)))
#define CPN(dst, offset, src) \
  (strncpy((dst)+(offset), (src), sizeof(dst)-(offset)))

static void
process_request(struct pty_state *state,
		const struct pty_message *request,
		struct pty_message *response)
{
  struct pty_object *pty;

  response->header.type = 0;
  response->header.ref = -1;
  response->header.length = 0;
  response->data = NULL;
  response->has_creds = 0;
  response->fd = -1;

  /* Require credentials for all requests */
  if (!request->has_creds)
    {
      werror("Missing credentials.\n");
      response->header.type = EPERM;
      return;
    }

  if (state->uid != (uid_t) -1
      && request->creds.uid != state->uid)
    {
      response->header.type = EPERM;
      return;
    }

  if (request->header.ref == -1)
    pty = NULL;
  else if (request->header.ref < 0
	   || (unsigned) request->header.ref >= state->nobjects)
    {
      response->header.type = EINVAL;
      return;
    }
  else
    {
      pty = &state->objects[request->header.ref];
      if (pty->free)
	{
	  response->header.type = EINVAL;
	  return;
	}
    }

  switch(request->header.type)
    {
    case PTY_REQUEST_CREATE:
      werror("PTY_REQUEST_CREATE\n");
      if (request->header.ref != -1)
	{
	  response->header.type = EINVAL;
	}
      else
	{
	  unsigned index;

	  pty = pty_object_alloc(state, &index);
	  if (!pty)
	    {
	      response->header.type = ENOMEM;
	    }
	  else
	    {
	      pty->uid = request->creds.uid;

	      if (request->fd != -1)
		{
		  /* Client can supply the master fd, so we can get
		     the slave tty name from there. */
		  char *tty = ptsname(request->fd);
		  if (tty)
		    tty = strdup(tty);
		  
		  if (!tty)
		    {
		      response->header.type = errno;
		      pty_object_free(state, index);
		      return;
		    }
		  pty->tty = tty;
		  /* FIXME: We could stat the tty and check ownership? */
		}
	      response->header.ref = index;
	    }
	}
      break;

    case PTY_REQUEST_MASTER:
      werror("PTY_REQUEST_MASTER\n");
      response->header.type = EOPNOTSUPP;

      /* Useful only for old bsd-style tty allocation. When using
	 /devptmx and grantpt, it's better to let the client create
	 the pty, since it will get the right ownership from the
	 start. */
#if 0
      if (request->header.ref != -1)
	{
	  response->header.type = EINVAL;
	}
      else
	{
	  unsigned index;
	  const char *tty;

	  pty = pty_object_alloc(state, &index);
	  if (!pty)
	    {
	      response->header.type = ENOMEM;
	      return;
	    }

	  response->fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	  if (response->fd < 0)
	    {
	      pty_object_free(state, index);
	      response->header.type = errno;
	      return;
	    }
      
	  tty = ptsname(response->fd);
	  if (!tty)
	    {
	      response->header.type = errno;
	    fail_and_close:

	      pty_object_free(state, index);
	      close(response->fd);
	      response->fd = -1;
	      return;
	    }

	  /* Copy, since ptsname returns a statically allocated value */
	  pty->tty = strdup(tty);
	  if (!pty->tty)
	    {
	      response->header.type = errno;
	      goto fail_and_close;
	    }

	  pty->uid = request->creds.uid;
      
	  if (pty->uid == getuid())
	    {
	      /* Use standard grantpt call */
	      if (grantpt(response->fd) < 0)
		{
		  response->header.type = errno;
		  goto fail_and_close;
		} 
	    }
	  else
	    {
	      gid_t gid = state->tty_gid;
	      if (gid == (gid_t) -1)
		gid = request->creds.gid;
	  
	      response->header.type
		= pty_set_permissions(pty->tty, pty->uid, gid);

	      if (response->header.type)
		goto fail_and_close;
	    }

	  if (unlockpt(response->fd < 0))
	    {
	      response->header.type = errno;
	      goto fail_and_close;
	    } 

	  response->header.ref = index;
	  response->length = strlen(pty->tty);
	  response->data = pty->tty;
	}
#endif
      break;

    case PTY_REQUEST_LOGIN:
      werror("PTY_REQUEST_LOGIN\n");
      if (!pty)
	{
	  response->header.type = EINVAL;
	}
      else if (request->creds.uid != pty->uid)
	{
	  response->header.type = EPERM;
	}
      else if (pty->active)
	{
	  response->header.type = EEXIST;
	}
      else
	{
	  response->header.ref = request->header.ref;

	  memset(&pty->entry, 0, sizeof(pty->entry));

	  pty->entry.ut_type = USER_PROCESS;
	  pty->entry.ut_pid = request->creds.pid;

#if 0
	  CP(pty->entry.ut_user, state->user_name);
#endif
	  
	  gettimeofday(&pty->entry.ut_tv, NULL);
	  
	  if (pty->tty)
	    {
	      /* Set tty-related fields, and update utmp */

	      const char *line;
	      
	      if (strprefix_p("/dev/", pty->tty))
		line = pty->tty + 5;
	      else
		line = pty->tty;
	  
	      CP(pty->entry.ut_line, line);

	      if (strprefix_p("pts/", line))
		{
		  pty->entry.ut_id[0] = 'p';
		  CPN(pty->entry.ut_id, 1, line + 4);
		}
	      else if (strprefix_p("tty", line))
		CP(pty->entry.ut_id, line + 3);
	      else
		CP(pty->entry.ut_id, line);

	      setutxent();

	      if (!pututxline(&pty->entry))
		werror("pututxline failed.\n");
	    }
	  
	  updwtmpx(wtmp_file, &pty->entry);

	  pty->active = 1;
	  break;
	}

    case PTY_REQUEST_LOGOUT:
      werror("PTY_REQUEST_LOGOUT\n");
      if (!pty)
	{
	  response->header.type = EINVAL;
	}
      else
	{
	  if (pty->active)
	    {
	      pty->entry.ut_type = DEAD_PROCESS;
	      gettimeofday(&pty->entry.ut_tv, NULL);

	      if (pty->tty)
		{
		  setutxent();

		  if (!pututxline(&pty->entry))
		    werror("pututxline failed.\n");
		}
	      updwtmpx(wtmp_file, &pty->entry);
	    }
	  pty_object_free(state, request->header.ref);
	}
      break;

    case PTY_REQUEST_DESTROY:
      werror("PTY_REQUEST_DESTROY\n");
      if (!pty)
	{
	  response->header.type = EINVAL;
	}
      else
	{
	  /* This request shouldn't rellay be used for "active" ptys,
	     i.e., if we have an utmp entry to clean up. */
	     
	  pty_object_free(state, request->header.ref);
	}
      break;

    default:
      response->header.type = EINVAL;
      break;
    }
}

int
main (int argc UNUSED, char **argv UNUSED)
{
  struct pty_state state;
  struct pty_message request;
  struct pty_message response;
  const char *utmp_file;
  int err;

  utmp_file = getenv(ENV_LSHD_UTMP);
  if (utmp_file)
    {
      werror("utmp_file: %s\n", utmp_file);
      utmpxname(utmp_file);
    }
  
  wtmp_file = getenv(ENV_LSHD_WTMP);
  if (!wtmp_file)
    {
#ifdef _WTMPX_FILE
      wtmp_file = _WTMPX_FILE;
#else
      wtmp_file = _PATH_WTMPX;
#endif
    }

  werror("wtmp_file: %s\n", wtmp_file);

#if defined (SO_PASSCRED)
  /* For Linux */
  {
    int yes = 1;

    if (setsockopt(STDIN_FILENO, SOL_SOCKET, SO_PASSCRED,
		   &yes, sizeof(yes)) < 0)
      {
	die("setsockopt SO_PASSCRED failed: %s.\n", strerror(errno));
	return EXIT_FAILURE;
      }
  }
#elif defined (SO_RECVUCRED)
  {
    int yes = 1;

    if (setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RECVUCRED,
		   &yes, sizeof(yes)) < 0)
      {
	die("setsockopt SO_PASSCRED failed: %s.\n", strerror(errno));
	return EXIT_FAILURE;
      }
  }
#endif

  init_pty_state(&state, getuid());
  if (!state.uid )
    {
      /* Currently, doesn't support running as root. And it makes no
	 sense to run as root unless SCM_CREDENTIALS passing is
	 supported. */
      return EXIT_FAILURE;
    }

  /* Do we need to clean up on exit? If the client, i.e.,
     lshd-connection, dies, the processes will be inherited by init.
     Than init should be able to clean up. The problematic case is if
     our client calls waitpid, and then dies before requesting a
     logout action, but we can probably just ignore that. */

  for (;;)
    {
      err = pty_recv_message(STDIN_FILENO, &request);
      if (err == -1)
	break;
      else if (err)
	die("pty_recv_message failed: %s.\n", strerror(err));

      process_request(&state, &request, &response);
      if (request.fd != -1)
	close(request.fd);

      err = pty_send_message(STDOUT_FILENO, &response);

      if (response.fd != -1)
	close(response.fd);
      
      if (err)
	die("pty_recv_message failed: %s.\n", strerror(err));
    }
  return EXIT_SUCCESS;
}
