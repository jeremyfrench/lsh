/* connection_commands.c
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

#include "connection_commands.h"

#include "connection.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "connection_commands.h.x"
#undef GABA_DEFINE

#if 0
#include "connection_commands.c.x"
#endif

static void
do_connection_remember(struct command *s,
		       struct lsh_object *x,
		       struct command_continuation *c,
		       struct exception_handler *e UNUSED)
{
  CAST(connection_command, self, s);
  CAST_SUBTYPE(resource, resource, x);

  if (resource)
    REMEMBER_RESOURCE(self->connection->resources, resource);

  COMMAND_RETURN(c, resource);
}

DEFINE_COMMAND_SIMPLE(connection_remember, a)
{
  CAST(ssh_connection, connection, a);
  NEW(connection_command, self);

  self->super.call = do_connection_remember;
  self->connection = connection;

  return &self->super.super;
}

/* (connection_if_srp then_f else_f connection)
 *
 * Invokes either (then_f connection) or (else_f connection)
 * depending on whether or not the CONNECTION_SRP flag is set.
 */

DEFINE_COMMAND3(connection_if_srp)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct lsh_object *a3,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, then_f, a1);
  CAST_SUBTYPE(command, else_f, a2);
  CAST(ssh_connection, connection, a3);
  
  struct command *f = ( (connection->flags & CONNECTION_SRP)
			? then_f : else_f);
  COMMAND_CALL(f, connection, c, e);
}

struct command *
make_connection_if_srp(struct command *then_f,
		       struct command *else_f)
{
  return make_command_3_invoke_2(&connection_if_srp,
				 &then_f->super,
				 &else_f->super);
}


DEFINE_COMMAND(connection_require_userauth)
     (struct command *s UNUSED, struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(ssh_connection, connection, a);

  if (connection->user)
    COMMAND_RETURN(c, connection);
  else
    EXCEPTION_RAISE(connection->e,
		    make_protocol_exception(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
					    "Access denied."));
}
