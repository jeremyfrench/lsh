/* io_commands.c
 *
 * $Id$
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

#include "io_commands.h"

#include "command.h"
#include "connection.h"
/* For lsh_get_cstring */
#include "format.h"
#include "io.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* Needed only to get the error code from failed calls to io_connect */
#include <errno.h>

/* For STDIN_FILENO */
#include <unistd.h>

#define GABA_DEFINE
#include "io_commands.h.x"
#undef GABA_DEFINE

#if WITH_TCPWRAPPERS
#include <tcpd.h> 

/* This seems to be neccesary on some systems */
#include <syslog.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;

#endif /* WITH_TCPWRAPPERS */

#include "io_commands.c.x"

/* Used only by lsh-writekey */

/* (write file_info)
 *
 * Opens a file for write, and returns the corresponding write_buffer.
 * */

DEFINE_COMMAND(io_write_file_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(io_write_file_info, info, a);

  struct lsh_fd *fd = io_write_file(lsh_get_cstring(info->name),
				    info->flags,
				    info->mode,
				    info->block_size,
				    NULL,
				    e);
  if (fd)
    COMMAND_RETURN(c, fd->write_buffer);
  else
    EXCEPTION_RAISE(e, make_io_exception(EXC_IO_OPEN_WRITE, NULL, errno, NULL));
}

struct io_write_file_info *
make_io_write_file_info(struct lsh_string *name, int flags, int mode, UINT32 block_size)
{
  NEW(io_write_file_info, self);
  self->name = name;
  self->flags = flags;
  self->mode = mode;
  self->block_size = block_size;

  return self;
}


static struct exception resolve_exception =
STATIC_EXCEPTION(EXC_RESOLVE, "address could not be resolved");

/* Used by do_listen_callback and any other listen variants. Currently
 * doesn't perform any dns lookups. */
static void
do_listen(struct address_info *a,
	  /* Continuation if listen succeeds. */
	  struct command_continuation *listen_c,
	  /* Continuation if accept succeeds. */
	  struct command_continuation *accept_c,
	  struct exception_handler *e)
{
  struct sockaddr *addr;
  socklen_t addr_length;
  
  struct lsh_fd *fd;

  addr = address_info2sockaddr(&addr_length, a, NULL, 0);
  if (!addr)
    {
      EXCEPTION_RAISE(e, &resolve_exception);
      return;
    }

  fd = io_listen(addr, addr_length,
		 make_listen_callback(accept_c, e),
		 e);
  lsh_space_free(addr);
  
  if (!fd)
    EXCEPTION_RAISE(e, make_io_exception(EXC_IO_LISTEN,
					 NULL, errno, NULL));
  else
    COMMAND_RETURN(listen_c, fd);
}

/* A listen function taking two arguments:
 * (listen callback port).
 *
 * Suitable for handling forwarding requests. NOTE: The calling
 * function has to do all remembering of the fd:s. */

DEFINE_COMMAND2(listen_with_callback)
     (struct command_2 *s UNUSED,
      struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, callback, a1);
  CAST(address_info, address, a2);

  /* No dns lookups */
  do_listen(address,
	    c,
	    make_apply(callback,
		       &discard_continuation, e), e);
}


/* GABA:
   (class
     (name connect_continuation)
     (super command_continuation)
     (vars
       (target object address_info)
       (up object command_continuation)))
*/

static void
do_connect_continuation(struct command_continuation *c,
			struct lsh_object *x)
{
  CAST(connect_continuation, self, c);
  CAST(lsh_fd, fd, x);

  COMMAND_RETURN(self->up, make_listen_value(fd, self->target));
}

static struct command_continuation *
make_connect_continuation(struct address_info *target,
			  struct command_continuation *up)
{
  NEW(connect_continuation, self);
  self->super.c = do_connect_continuation;
  self->target = target;
  self->up = up;

  return &self->super;
}
     
static void
do_connect(struct address_info *a,
	   struct resource_list *resources,
	   struct command_continuation *c,
	   struct exception_handler *e)
{
  struct sockaddr *addr;
  socklen_t addr_length;
  struct lsh_fd *fd;

  /* Address must specify a host */
  assert(a->ip);

  /* Performs dns lookups */
  addr = address_info2sockaddr(&addr_length, a, NULL, 1);
  if (!addr)
    {
      EXCEPTION_RAISE(e, &resolve_exception);
      return;
    }

  /* If the name is canonicalized in any way, we should pass the
   * canonical name to make_connect_continuation .*/
  fd = io_connect(addr, addr_length, 
		  make_connect_continuation(a, c), e);
  lsh_space_free(addr);

  if (!fd)
    {
      EXCEPTION_RAISE(e, make_io_exception(EXC_IO_CONNECT, NULL, errno, NULL));
      return;
    }

  if (resources)
    remember_resource(resources,
		      &fd->super);
}


/* Connect variant, taking a connection object as argument (used for
 * rememembering the connected fd).
 *
 * (connect port connection) -> fd */

/* GABA:
   (class
     (name connect_port)
     (super command)
     (vars
       (target object address_info)))
*/

static void
do_connect_port(struct command *s,
		struct lsh_object *x,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(connect_port, self, s);
  CAST(ssh_connection, connection, x);
  
  do_connect(self->target, connection->resources, c, e);
}


struct command *
make_connect_port(struct address_info *target)
{
  NEW(connect_port, self);
  self->super.call = do_connect_port;
  self->target = target;

  return &self->super;
}

/* (connect address) */
DEFINE_COMMAND(connect_simple_command)
     (struct command *self UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(address_info, address, a);

  do_connect(address, NULL, c, e);
}


/* (connect_connection connection port) */
DEFINE_COMMAND2(connect_connection_command)
     (struct command_2 *self UNUSED,
      struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(ssh_connection, connection, a1);
  CAST(address_info, address, a2);

  do_connect(address, connection->resources, c, e);
}


/* GABA:
   (class
     (name listen_local)
     (super command)
     (vars
       (info object local_info)))
*/

static void
do_listen_local(struct command *s,
		struct lsh_object *x,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(listen_local, self, s);
  CAST_SUBTYPE(command, callback, x);
  
  struct lsh_fd *fd
    = io_listen_local(self->info,
		      make_listen_callback(make_apply(callback,
						      &discard_continuation, e),
					   e),
		      e);
  if (!fd)
    EXCEPTION_RAISE(e, make_io_exception(EXC_IO_LISTEN,
					 NULL, errno, NULL));
  else
    COMMAND_RETURN(c, fd);
}

struct command *
make_listen_local(struct local_info *info)
{
  NEW(listen_local, self);
  self->info = info;

  self->super.call = do_listen_local;

  return &self->super;
}

/* ;; GABA:
   (class
     (name connect_local)
     (super command)
     (vars
       (backend object io_backend)))
*/

#if 0
static void
do_connect_local(struct command *self,
                 struct lsh_object *x,
                 struct command_continuation *c,
                 struct exception_handler *e)
{
  CAST(local_info, info, x);

  io_connect_local(info,
		   make_connect_continuation(NULL, c),
		   e);
}

struct command *
make_connect_local(void)
{
  NEW(connect_local, self);

  self->call = do_connect_local;

  return self;
}
#endif

DEFINE_COMMAND(connect_local_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(local_info, info, a);

  io_connect_local(info,
		   make_connect_continuation(NULL, c),
		   e);
}


/* Takes a listen_value as argument, logs the peer address, and
 * returns the fd object. */

DEFINE_COMMAND(io_log_peer_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(listen_value, lv, a);

  verbose("Accepting connection from %S, port %i\n",
	  lv->peer->ip, lv->peer->port);

  COMMAND_RETURN(c, lv);
}






/* GABA:
   (class
     (name tcp_wrapper)
     (super command)
     (vars
       (name string)
       (msg string)))
*/


/* TCP wrapper function, replaces io_log_peer if used */

static void
do_tcp_wrapper(struct command *s UNUSED,
	       struct lsh_object *a,
	       struct command_continuation *c,
	       struct exception_handler *e UNUSED)
{
  CAST(listen_value, lv, a);

#if WITH_TCPWRAPPERS  

  CAST(tcp_wrapper, self, s);

  struct request_info res;

  request_init(&res,
	       RQ_DAEMON, lsh_get_cstring(self->name), /* Service name */
	       RQ_FILE, lv->fd->fd,   /* connection fd */
	       0);                /* No more arguments */
  
  fromhost(&res); /* Lookup information before */
  
  if (!hosts_access(&res)) /* Connection OK? */
    { 
      /* FIXME: Should we say anything to the other side? */

      verbose("Denying access for %z@%z (%z)\n",
	      eval_user(&res),
	      eval_hostname(res.client),
	      eval_hostaddr(res.client)
	      );


      
      io_write(lv->fd, 1024, NULL);
      A_WRITE(&lv->fd->write_buffer->super, 
	      self->msg);

      close_fd_nicely(lv->fd);

      return;
    }

#endif /* WITH_TCPWRAPPERS */
  
  verbose("Accepting connection from %S, port %i\n",
	  lv->peer->ip, lv->peer->port);
  
  COMMAND_RETURN(c, lv);
}



struct command *
make_tcp_wrapper(struct lsh_string *name, struct lsh_string *msg )
{
  NEW(tcp_wrapper, self);
  self->super.call = do_tcp_wrapper;
  self->name = name;
  self->msg = msg;

  return &self->super;
}

/* ***
 *
 * (lambda (backend connection port)
     (listen backend connection port
             (lambda (peer)
                (start-io peer (request-forwarded-tcpip connection peer)))))
 */
