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
#include "io.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* Needed only to get the error code from failed calls to io_connect() */
#include <errno.h>

/* For STDIN_FILENO */
#include <unistd.h>

#define GABA_DEFINE
#include "io_commands.h.x"
#undef GABA_DEFINE

#include "io_commands.c.x"

/* GABA:
   (class
     (name backend_command)
     (super command)
     (vars
       (backend object io_backend)))
*/

/* (write file_info backend)
 *
 * Opens a file for write, and returns the corresponding write_buffer.
 * */
   
static void
do_io_write_file(struct command *s,
		 struct lsh_object *a,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  CAST(backend_command, self, s);
  CAST(io_write_file_info, info, a);

  struct lsh_fd *fd = io_write_file(self->backend,
				    info->name,
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

COMMAND_SIMPLE(io_write_file_command)
{
  CAST(io_backend, backend, a);

  NEW(backend_command, self);
  self->super.call = do_io_write_file;
  self->backend = backend;

  return &self->super.super;
}

struct io_write_file_info *
make_io_write_file_info(const char *name, int flags, int mode, UINT32 block_size)
{
  NEW(io_write_file_info, self);
  self->name = name;
  self->flags = flags;
  self->mode = mode;
  self->block_size = block_size;

  return self;
}

void do_io_read_fd(struct command *s,
		   struct lsh_object *a,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(io_read_fd, self, s);
  CAST(io_backend, backend, a);

  COMMAND_RETURN(c, make_lsh_fd(backend, self->fd, e));
}

struct io_read_fd io_read_stdin
= STATIC_IO_READ_FD(STDIN_FILENO);

#if 0
/* ;; GABA:
   (class
     (name listen_command_callback)
     (super fd_listen_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)
       (e object exception_handler)))
*/

static void
do_listen_continue(struct fd_listen_callback *s, int fd,
		   struct address_info *peer)
{
  CAST(listen_command_callback, self, s);

  COMMAND_RETURN(self->c,
		 make_listen_value(make_lsh_fd(self->backend, fd, self->e),
				   peer));
}

static struct fd_listen_callback *
make_listen_command_callback(struct io_backend *backend,
			     struct command_continuation *c,
			     struct exception_handler *e)
{
  NEW(listen_command_callback, closure);
  closure->backend = backend;
  closure->c = c;
  closure->e = e;
  closure->super.f = do_listen_continue;
  
  return &closure->super;
}
#endif

/* GABA:
   (class
     (name remember_continuation)
     (super command_continuation)
     (vars
       (resources object resource_list)
       (up object command_continuation)))
*/

static void
do_remember_continuation(struct command_continuation *s,
			 struct lsh_object *x)
{
  CAST(remember_continuation, self, s);
  CAST_SUBTYPE(resource, resource, x);

  assert(resource);
  REMEMBER_RESOURCE(self->resources, resource);

  COMMAND_RETURN(self->up, resource);
}

struct command_continuation *
make_remember_continuation(struct resource_list *resources,
			   struct command_continuation *up)
{
  NEW(remember_continuation, self);
  self->super.c = do_remember_continuation;

  self->resources = resources;
  self->up = up;

  return &self->super;
}

static struct exception resolve_exception =
STATIC_EXCEPTION(EXC_RESOLVE, "address could not be resolved");

/* Used by both do_simple_listen and do_listen_connection. */
static void
do_listen(struct io_backend *backend,
	  struct address_info *a,
	  int lookup,
	  struct resource_list *resources,
	  /* Continuation if listen() succeeds. */
	  struct command_continuation *listen_c,
	  /* Continuation if accept() succeeds. */
	  struct command_continuation *accept_c,
	  struct exception_handler *e)
{
  struct sockaddr *addr;
  socklen_t addr_length;
  
  struct lsh_fd *fd;

  addr = address_info2sockaddr(&addr_length, a, NULL, lookup);
  if (!addr)
    {
      EXCEPTION_RAISE(e, &resolve_exception);
      return;
    }

  if (resources)
    accept_c = make_remember_continuation(resources, accept_c);
  
  fd = io_listen(backend,
		 addr, addr_length,
		 make_listen_callback(backend, accept_c, e),
		 e);
  lsh_space_free(addr);
  
  if (!fd)
    {
      EXCEPTION_RAISE(e, make_io_exception(EXC_IO_LISTEN,
					   NULL, errno, NULL));
    }
  else
    {
      if (resources)
	REMEMBER_RESOURCE(resources, &fd->super);
      if (listen_c)
	COMMAND_RETURN(listen_c, fd);
    }
}

/* A listen function taking three arguments:
 * (listen callback backend port).
 *
 * Suitable for handling forwarding requests.
 * NOTE: The calling function has to do all remembering of the fd:s. */

/* GABA:
   (class
     (name listen_with_callback)
     (super command)
     (vars
       (callback object command)
       (backend object io_backend)))
*/

static void
do_listen_with_callback(struct command *s,
			struct lsh_object *x,
			struct command_continuation *c,
			struct exception_handler *e)
{
  CAST(listen_with_callback, self, s);
  CAST(address_info, address, x);

  /* No dns lookups */
  do_listen(self->backend, address, 0,
	    NULL, /* FIXME: resources */
	    c,
	    make_apply(self->callback,
		       &discard_continuation, e), e);
#if 0
  struct sockaddr *addr;
  socklen_t addr_length;

  /* Doesn't do any dns lookups. */
  addr = address_info2sockaddr(&addr_length, address, NULL, 0);
  if (!addr)
    {
      EXCEPTION_RAISE(e, &resolve_exception);
      return;
    }

  /* FIXME: Asyncronous dns lookups should go here */
  fd = io_listen(self->backend,
		 addr, addr_length,
		 make_listen_callback
		 (self->backend,
		  make_apply(self->callback,
			     &discard_continuation, e), e), e);
  lsh_space_free(addr);

  if (fd)
    COMMAND_RETURN(c, fd);
  else
    EXCEPTION_RAISE(e,
		    make_io_exception(EXC_IO_LISTEN, NULL,
				      errno, NULL));
#endif
}

struct command *
make_listen_with_callback(struct command *callback,
			  struct io_backend *backend)
{
  NEW(listen_with_callback, self);
  self->callback = callback;
  self->backend = backend;

  self->super.call = do_listen_with_callback;

  return &self->super;
}

static struct lsh_object *
collect_listen_callback(struct collect_info_2 *info,
			struct lsh_object *a,
			struct lsh_object *b)
{
  CAST_SUBTYPE(command, callback, a);
  CAST(io_backend, backend, b);
  assert(!info->next);

  return &make_listen_with_callback(callback, backend)->super;
}

static struct collect_info_2 collect_info_listen_callback_2 =
STATIC_COLLECT_2_FINAL(collect_listen_callback);

struct collect_info_1 listen_with_callback =
STATIC_COLLECT_1(&collect_info_listen_callback_2);


/* A listen function taking three arguments:
 * (listen backend connection port).
 *
 * Suitable for handling forwarding requests. Adds all fd:s to the
 * connection's resource list automatically.
 *
 * NOTE: On second thought, this is not terribly useful, because
 * accepted fd:s should usually be registered on a channels's resource
 * list, not on the connection's. */

/* GABA:
   (class
     (name listen_with_connection)
     (super command)
     (vars
       (connection object ssh_connection)
       (backend object io_backend)))
*/

static void
do_listen_with_connection(struct command *s,
			  struct lsh_object *x,
			  struct command_continuation *c,
			  struct exception_handler *e)
{
  CAST(listen_with_connection, self, s);
  CAST(address_info, address, x);

  /* No dns lookups */
  do_listen(self->backend, address, 0,
	    self->connection->resources,
	    NULL,
	    c, e);
}

struct command *
make_listen_with_connection(struct io_backend *backend,
			    struct ssh_connection *connection)
{
  NEW(listen_with_connection, self);
  self->connection = connection;
  self->backend = backend;

  self->super.call = do_listen_with_connection;

  return &self->super;
}

static struct lsh_object *
collect_listen_connection(struct collect_info_2 *info,
			  struct lsh_object *a,
			  struct lsh_object *b)
{
  CAST(io_backend, backend, a);
  CAST(ssh_connection, connection, b);
  assert(!info->next);

  return &make_listen_with_connection(backend, connection)->super;
}

static struct collect_info_2 collect_info_listen_connection_2 =
STATIC_COLLECT_2_FINAL(collect_listen_connection);

struct collect_info_1 listen_with_connection =
STATIC_COLLECT_1(&collect_info_listen_connection_2);


#if 0
/* FIXME: This could perhaps be merged with io_connect in io.c? */ 
/* ;; GABA:
   (class
     (name connect_command_callback)
     (super fd_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)
       (e object exception_handler)))
*/

/* FIXME: The new fd object should be added to the same resource list
 * as the old one. Perhaps the connection code in io.c should reuse
 * the fd object in some way? */
static void
do_connect_continue(struct fd_callback **s, int fd)
{
  CAST(connect_command_callback, self, *s);

  assert(fd >= 0);

  COMMAND_RETURN(self->c, make_lsh_fd(self->backend, fd, self->e));
}

static struct fd_callback *
make_connect_command_callback(struct io_backend *backend,
			      struct command_continuation *c,
			      struct exception_handler *e)
{
  NEW(connect_command_callback, closure);
  closure->backend = backend;
  closure->c = c;
  closure->e = e;
  closure->super.f = do_connect_continue;
  
  return &closure->super;
}
#endif

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
do_connect(struct io_backend *backend,
	   struct address_info *a,
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
   * canonical name to make_connect_continuation() .*/
  fd = io_connect(backend, addr, addr_length, 
		  make_connect_continuation(a, c), e);
  lsh_space_free(addr);

  if (!fd)
    {
      EXCEPTION_RAISE(e, make_io_exception(EXC_IO_CONNECT, NULL, errno, NULL));
      return;
    }

  if (resources)
    REMEMBER_RESOURCE(resources,
		      &fd->super);
}


/* Connect variant, taking a connection object as argument (used for
 * rememembering the connected fd).
 *
 * (connect backend port connection) -> fd */

/* GABA:
   (class
     (name connect_port)
     (super command)
     (vars
       (backend object io_backend)
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
  
  do_connect(self->backend, self->target, connection->resources, c, e);
}


struct command *
make_connect_port(struct io_backend *backend,
		  struct address_info *target)
{
  NEW(connect_port, self);
  self->super.call = do_connect_port;
  self->backend = backend;
  self->target = target;

  return &self->super;
}

static struct lsh_object *
collect_connect_port(struct collect_info_2 *info,
		     struct lsh_object *a,
		     struct lsh_object *b)
{
  CAST(io_backend, backend, a);
  CAST(address_info, target, b);
  assert(!info->next);
  assert(backend);
  assert(target);
  
  return &make_connect_port(backend, target)->super;
}

static struct collect_info_2 collect_info_connect_port_2 =
STATIC_COLLECT_2_FINAL(collect_connect_port);

struct collect_info_1 connect_with_port =
STATIC_COLLECT_1(&collect_info_connect_port_2);


/* GABA:
   (class
     (name simple_io_command)
     (super command)
     (vars
       (backend object io_backend)
       (resources object resource_list)))
*/

/* Simple connect function taking port only as argument. Also used for
 * listen.
 *
 * (connect address) */

static void
do_simple_connect(struct command *s,
		  struct lsh_object *a,
		  struct command_continuation *c,
		  struct exception_handler *e)
{
  CAST(simple_io_command, self, s);
  CAST(address_info, address, a);

  do_connect(self->backend, address, NULL, c, e);
}

struct command *
make_simple_connect(struct io_backend *backend,
		    struct resource_list *resources)
{
  NEW(simple_io_command, self);
  self->backend = backend;
  self->resources = resources;
  
  self->super.call = do_simple_connect;

  return &self->super;
}


/* (connect connection port) */
/* GABA:
   (class
     (name connect_connection)
     (super command)
     (vars
       (backend object io_backend)))
*/

static void
do_connect_connection(struct command *s,
		      struct lsh_object *x,
		      struct command_continuation *c,
		      struct exception_handler *e UNUSED)
{
  CAST(connect_connection, self, s);
  CAST(ssh_connection, connection, x);

  COMMAND_RETURN(c,
		 make_simple_connect(self->backend, connection->resources));
}

struct command *
make_connect_connection(struct io_backend *backend)
{
  NEW(connect_connection, self);
  self->super.call = do_connect_connection;
  self->backend = backend;

  return &self->super;
}


static void
do_simple_listen(struct command *s,
		 struct lsh_object *a,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  CAST(simple_io_command, self, s);
  CAST(address_info, address, a);

  /* Performs a dns lookup, if needed. */
  do_listen(self->backend, address, 1, NULL, NULL, c, e);
}

/* FIXME: The resources argument is never used. */
struct command *
make_simple_listen(struct io_backend *backend,
		   struct resource_list *resources)
{
  NEW(simple_io_command, self);
  self->backend = backend;
  self->resources = resources;
  
  self->super.call = do_simple_listen;

  return &self->super;
}


/* Takes a listen_value as argument, logs the peer address, and
 * returns the fd object. */

COMMAND_SIMPLE(io_log_peer_command)
{
  CAST(listen_value, lv, a);

  verbose("Accepting connection from %S, port %i\n",
	  lv->peer->ip, lv->peer->port);

  return &lv->super;
}


/* ***
 *
 * (lambda (backend connection port)
     (listen backend connection port
             (lambda (peer)
                (start-io peer (request-forwarded-tcpip connection peer)))))
 */
