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

#define GABA_DEFINE
#include "io_commands.h.x"
#undef GABA_DEFINE

#include "io_commands.c.x"

/* GABA:
   (class
     (name listen_command_callback)
     (super fd_listen_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)))
*/

static int do_listen_continue(struct fd_listen_callback *s, int fd,
			      struct address_info *peer)
{
  CAST(listen_command_callback, self, s);
  NEW(listen_value, res);

  res->fd = make_io_fd(self->backend, fd);
  res->peer = peer;

  return COMMAND_RETURN(self->c, res);
}

static struct fd_listen_callback *
make_listen_command_callback(struct io_backend *backend,
			     struct command_continuation *c)
{
  NEW(listen_command_callback, closure);
  closure->backend = backend;
  closure->c = c;
  closure->super.f = do_listen_continue;
  
  return &closure->super;
}

static int do_listen(struct io_backend *backend,
		     struct address_info *a,
		     struct resource_list *resources,
		     struct command_continuation *c)
{
  /* FIXME: Add ipv6 support somewhere */
  struct sockaddr_in sin;
  struct listen_fd *fd;
  
  if (!address_info2sockaddr_in(&sin, a))
    return COMMAND_RETURN(c, NULL);

  fd = io_listen(backend, &sin,
		 make_listen_command_callback(backend, c));

  if (!fd)
    /* NOTE: Will never invoke the continuation. */
    return LSH_COMMAND_FAILED;

  if (resources)
    REMEMBER_RESOURCE(resources, &fd->super.super);
  
  return LSH_OK | LSH_GOON;
}

/* A listen function taking three arguments:
 * (listen callback backend port).
 *
 * Suitable for handling forwarding requests. */

/* GABA:
   (class
     (name listen_connection)
     (super command)
     (vars
       (callback object command)
       (backend object io_backend)))
       ;; (connection object ssh_connection)))
*/

static int
do_listen_connection(struct command *s,
		     struct lsh_object *x,
		     struct command_continuation *c)
{
  CAST(listen_connection, self, s);
  CAST(address_info, address, x);

  /* FIXME: Add ipv6 support somewhere */
  struct sockaddr_in sin;
  
  if (!address_info2sockaddr_in(&sin, address))
    return COMMAND_RETURN(c, NULL);

  /* FIXME: Asyncronous dns lookups should go here */
  return COMMAND_RETURN(c, io_listen
			(self->backend, &sin,
			 make_listen_command_callback
			 (self->backend,
			  make_apply(self->callback, NULL))));
		 
}

struct command *make_listen_command(struct command *callback,
				    struct io_backend *backend)
{
  NEW(listen_connection, self);
  self->callback = callback;
  self->backend = backend;

  self->super.call = do_listen_connection;

  return &self->super;
}

static struct lsh_object *
collect_listen(struct collect_info_2 *info,
	       struct lsh_object *a,
	       struct lsh_object *b)
{
  CAST(io_backend, backend, a);
  CAST_SUBTYPE(command, callback, b);
  assert(!info);

  return &make_listen_command(callback, backend)->super;
}

static struct collect_info_2 collect_info_listen_2 =
STATIC_COLLECT_2_FINAL(collect_listen);

struct collect_info_1 listen_command =
STATIC_COLLECT_1(&collect_info_listen_2);



/* GABA:
   (class
     (name connect_command_callback)
     (super fd_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)))
*/

static int do_connect_continue(struct fd_callback **s, int fd)
{
  CAST(connect_command_callback, self, *s);

  return COMMAND_RETURN(self->c,
			((fd < 0)
			 ? NULL
			 : make_io_fd(self->backend, fd)));
}

static struct fd_callback *
make_connect_command_callback(struct io_backend *backend,
			      struct command_continuation *c)
{
  NEW(connect_command_callback, closure);
  closure->backend = backend;
  closure->c = c;
  closure->super.f = do_connect_continue;
  
  return &closure->super;
}

static int do_connect(struct io_backend *backend,
		      struct address_info *a,
		      struct resource_list *resources,
		      struct command_continuation *c)
{
  /* FIXME: Add ipv6 support somewhere */
  struct sockaddr_in sin;
  struct connect_fd *fd;

  /* Address must specify a host */
  assert(a->ip);
  
  if (!address_info2sockaddr_in(&sin, a))
    return COMMAND_RETURN(c, NULL);

  fd = io_connect(backend, &sin, NULL,
		  make_connect_command_callback(backend, c));

  if (!fd)
    return COMMAND_RETURN(c, NULL);

  if (resources)
    REMEMBER_RESOURCE(resources,
		      &fd->super.super);
  
  return LSH_OK | LSH_GOON;
}


/* Connect variant, taking a connection object as argument (used for
 * rememembering the connected fd). */

/* GABA:
   (class
     (name connect_connection)
     (super command)
     (vars
       (backend object io_backend)
       (target object address_info)))
*/

static int do_connect_connection(struct command *s,
				 struct lsh_object *x,
				 struct command_continuation *c)
{
  CAST(connect_connection, self, s);
  CAST(ssh_connection, connection, x);
  
  return do_connect(self->backend, self->target, connection->resources, c);
}


struct command *make_connect_connection(struct io_backend *backend,
					struct address_info *target)
{
  NEW(connect_connection, self);
  self->super.call = do_connect_connection;
  self->backend = backend;
  self->target = target;

  return &self->super;
}

static struct lsh_object *
collect_connect_connection(struct collect_info_2 *info,
			   struct lsh_object *a,
			   struct lsh_object *b)
{
  CAST(io_backend, backend, a);
  CAST(address_info, target, b);
  assert(!info);
  assert(backend);
  assert(target);
  
  return &make_connect_connection(backend, target)->super;
}

static struct collect_info_2 collect_info_connect_2 =
STATIC_COLLECT_2_FINAL(collect_connect_connection);

struct collect_info_1 connect_with_connection =
STATIC_COLLECT_1(&collect_info_connect_2);


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

static int do_simple_connect(struct command *s,
			     struct lsh_object *a,
			     struct command_continuation *c)
{
  CAST(simple_io_command, self, s);
  CAST(address_info, address, a);

  return do_connect(self->backend, address, self->resources, c);
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


static int do_simple_listen(struct command *s,
			    struct lsh_object *a,
			    struct command_continuation *c)
{
  CAST(simple_io_command, self, s);
  CAST(address_info, address, a);

  return do_listen(self->backend, address, self->resources, c);
}

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

static struct lsh_object *
do_simple_log_peer(struct command_simple *s UNUSED,
		   struct lsh_object *x)
{
  CAST(listen_value, a, x);

  verbose("Accepting connection from %S, port %i\n",
	  a->peer->ip, a->peer->port);

  return &a->fd->super.super.super;
}

struct command_simple io_log_peer_command =
STATIC_COMMAND_SIMPLE(do_simple_log_peer);
  
/* ***
 *
 * (lambda (backend connection port)
     (listen backend connection port
             (lambda (peer)
                (start-io peer (request-forwarded-tcpip connection peer)))))
 */
