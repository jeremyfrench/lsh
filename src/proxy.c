/* proxy.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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

#include "proxy.h"
#include "proxy_session.h"
#include "proxy_userauth.h"
#include "channel_commands.h"
#include "exception.h"
#include "xalloc.h"
#include "connection.h"
#include "command.h"
#include "format.h"
#include "io_commands.h"

#include <assert.h>
#include <arpa/inet.h>

#include "proxy.c.x"

/* GABA:
   (class
     (name chain_connections_continuation)
     (super command_frame)
     (vars
       (connection object ssh_connection)))
 */

static void
do_chain_connections_continuation(struct command_continuation *s,
				  struct lsh_object *x)
{
  CAST(chain_connections_continuation, self, s);
  CAST(ssh_connection, chained, x);

  self->connection->chain = chained;
  chained->chain = self->connection;
  COMMAND_RETURN(self->super.up, &self->connection->super.super);
}

static struct command_continuation *
make_chain_connections_continuation(struct ssh_connection *connection,
				   struct command_continuation *c)
{
  NEW(chain_connections_continuation, self);
  
  self->super.super.c = do_chain_connections_continuation;
  self->connection = connection;
  self->super.up = c;
  return &self->super.super;
}

/* GABA:
   (class
     (name chain_connections)
     (super command)
     (vars
       (callback object command)
       (lv object listen_value)))
*/

static void
do_chain_connections(struct command *s,
		     struct lsh_object *x,
		     struct command_continuation *c,
		     struct exception_handler *e)
{
  CAST(chain_connections, self, s);
  CAST(ssh_connection, connection, x);
  struct sockaddr_in sa;
  int salen = sizeof(sa);

  /* FIXME: support non AF_INET address families */
  if (getsockname(self->lv->fd->super.fd, (struct sockaddr *) &sa, &salen) != -1)
    {
      struct address_info *a;

      /*       
       * a = make_address_info(ssh_format("%z", inet_ntoa(sa.sin_addr)), sa.sin_port); 
       */
      a = make_address_info(ssh_format("localhost"), 1998);
      COMMAND_CALL(self->callback, &a->super, 
		   make_chain_connections_continuation(connection, c),
		   e);
    }

}

static struct command *
make_chain_connections(struct command *callback,
		       struct listen_value *lv)
{
  NEW(chain_connections, self);

  self->super.call = do_chain_connections;
  self->callback = callback;
  self->lv = lv;
  return &self->super;
}

static struct lsh_object *
do_collect_chain_params(struct collect_info_2 *info UNUSED,
			struct lsh_object *a,
			struct lsh_object *b)
{
  CAST_SUBTYPE(command, callback, a);
  CAST_SUBTYPE(listen_value, lv, b);

  return &make_chain_connections(callback, lv)->super;
}

struct collect_info_2 chain_connections_2 = 
STATIC_COLLECT_2_FINAL(do_collect_chain_params);

struct collect_info_1 chain_connections =
STATIC_COLLECT_1(&chain_connections_2);

/* gets two params: user connection ->
   handles user here, and returns a command taking a connection */
/* GABA:
   (class
     (name proxy_connection_service)
     (super command)
     (vars
       (session_requests object alist)))
*/

static void
do_login(struct command *s,
	 struct lsh_object *x UNUSED,
	 struct command_continuation *c,
	 struct exception_handler *e UNUSED)
{
  CAST(proxy_connection_service, self, s);

  COMMAND_RETURN(c, 
		 make_install_fix_channel_open_handler
		 (ATOM_SESSION, 
		  make_proxy_open_session(self->session_requests)));
}

struct command *
make_proxy_connection_service(struct alist *session_requests)
{
  NEW(proxy_connection_service, self);

  self->super.call = do_login;
  self->session_requests = session_requests;
  return &self->super;
}
