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

#include "connection.h"
#include "io.h"

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

  return COMMAND_RETURN(self->c, &res->super);
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
  
  if (!tcp_addr(&sin, a->address->length, a->address->data, a->port))
    return COMMAND_RETURN(c, NULL);

  fd = io_listen(self->backend, &sin,
		 make_listen_command_callback(backend, c));

  if (!fd)
    return COMMAND_RETURN(c, NULL);

  if (resources)
    REMEMBER_RESOURCE(connection->resources,
		      &fd->super.super);
  
  return LSH_OK | LSH_GOON;
}

/* A listen function taking three arguments:
 * (listen backend connection port).
 *
 * Suitable for handling forwarding requests. */

/* GABA:
   (class
     (name listen_connection)
     (super command)
     (vars
       (backend object io_backend)
       (connection object connection)))
*/

struct lsh_object *
do_listen_connection(struct command *s,
		     struct lsh_object *x,
		     struct command_continuation *c)
{
  CAST(listen_connection, self, s);
  CAST(address_info, address, x);
  return do_listen(self->backend, self->connection, address, c);
}

struct command *make_listen_connection(struct io_backend *backend,
				    struct ssh_connection *connection)
{
  NEW(listen_command, self);
  self->backend = backend;
  self->connection = connection;

  self->super.call = do_listen_connection;

  return &self->super;
}

static struct lsh_object *
do_collect_listen_connection(struct collect_info_2 *info,
			     struct lsh_object *b,
			     struct lsh_object *c)
{
  CAST(io_backend, backend, b);
  CAST(ssh_connection, connection, c);
  assert(!info);

  return &make_listen_connection(backend, connection)->super;
}

/* GABA:
   (class
     (name connect_command_callback)
     (super fd_connect_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)))
*/

static int do_connect_continue(struct fd_connect_callback *s, int fd)
{
  CAST(connect_command_callback, self, s);

  return COMMAND_RETURN(self->c, make_io_fd(self->backend, fd));
}

static struct fd_connect_callback *
make_connect_command_callback(struct io_backend *backend,
			      struct command_continuation *c)
{
  NEW(listen_command_callback, closure);
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
  
  if (!tcp_addr(&sin, a->address->length, a->address->data, a->port))
    return COMMAND_RETURN(c, NULL);

  fd = io_connect(self->backend, &sin,
		  make_connect_command_callback(backend, c));

  if (!fd)
    return COMMAND_RETURN(c, NULL);

  if (resources)
    REMEMBER_RESOURCE(connection->resources,
		      &fd->super.super);
  
  return LSH_OK | LSH_GOON;
}


/* Connect function, taking three arguments:
 *
 * (connect backend connection address)
 */


 
/* ***
 *
 * (lambda (backend connection port)
     (listen backend connection port
             (lambda (peer)
                (start-io peer (request-forwarded-tcpip connection peer)))))
 */
