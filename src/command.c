/* command.h
 *
 * $Id$ */

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

#include "command.h"

#include "connection.h"
#include "io.h"
#include "xalloc.h"

#define CLASS_DEFINE
#include "command.h.x"
#undef CLASS_DEFINE

#include "command.c.x"

/* CLASS:
   (class
     (name command_apply)
     (super command_frame)
     (vars
       (f object command)))
*/

static int do_command_apply(struct command_continuation *s,
			    struct lsh_object *value)
{
  CAST(command_apply, self, s);
  return COMMAND_CALL(self->f, value, self->super.up);
}

struct command_continuation *
make_apply(struct command *f, struct command_continuation *c)
{
  NEW(command_apply, res);
  res->f = f;
  res->super.up = c;
  res->super.super.c = do_command_apply;

  return &res->super.super;
}
    
/* Combinators */

/* Ix == x */
static int do_command_I(struct command *ignored UNUSED,
			struct lsh_object *arg,
			struct command_continuation *c)			
{
  return COMMAND_RETURN(c, arg);
}

struct command command_I =
{ STATIC_HEADER, do_command_I };

/* ((S f) g)x == (f x)(g x) */

/* Represents (S f) */
/* CLASS:
   (class
     (name command_S_1)
     (super command)
     (vars
       (f object command)))
*/

/* Represents ((S f) g) */
/* CLASS:
   (class
     (name command_S_2)
     (super command)
     (vars
       (f object command)
       (g object command)))
*/

/* Continuation called after evaluating (f x) */
/* CLASS:
   (class
     (name command_S_continuation)
     (super command_frame)
     (vars
       (g object command)
       (x object lsh_object)))
*/

static int do_command_S_continuation(struct command_continuation *c,
				     struct lsh_object *value)
{
  CAST(command_S_continuation, self, c);
  CAST_SUBTYPE(command, op, value);
  return COMMAND_CALL(self->g, self->x, make_apply(op, self->super.up));
}

static int do_command_S_2(struct command *s,
			  struct lsh_object *x,
			  struct command_continuation *up)
{
  CAST(command_S_2, self, s);
  NEW(command_S_continuation, c);
  c->g = self->g;
  c->x = x;
  c->super.up = up;
  c->super.super.c = do_command_S_continuation;
  
  return COMMAND_CALL(self->f, x, &c->super.super);
}

static int do_command_S_1(struct command *s,
			  struct lsh_object *a,
			  struct command_continuation *c)
			  
{
  CAST(command_S_1, self, s);
  CAST_SUBTYPE(command, arg, a);
  NEW(command_S_2, res);
  res->f = self->f;
  res->g = arg;
  
  res->super.call = do_command_S_2;

  return COMMAND_RETURN(c, &res->super.super);
}

static int do_command_S(struct command *ignored UNUSED,
			struct lsh_object *a,
			struct command_continuation *c)
{
  CAST_SUBTYPE(command, arg, a);
  NEW(command_S_1, res);
  res->f = arg;
  res->super.call = do_command_S_1;

  return COMMAND_RETURN(c, &res->super.super);
}

struct command command_S = { STATIC_HEADER, do_command_S };

/* ((B x) y) z == (x (y z)) */

/* Represents (B x) */
/* CLASS:
   (class
     (name command_B_1)
     (super command)
     (vars
       (x object command)))
*/

/* Represents ((B x) y) */
/* CLASS:
   (class
     (name command_B_2)
     (super command)
     (vars
       (x object command)
       (y object command)))
*/

static int do_command_B_2(struct command *s,
			  struct lsh_object *z,
			  struct command_continuation *c)
{
  CAST(command_B_2, self, s);
  return COMMAND_CALL(self->y, z, make_apply(self->x, c));
}

static int do_command_B_1(struct command *s,
			  struct lsh_object *a,
			  struct command_continuation *c)
{
  CAST(command_B_1, self, s);
  CAST_SUBTYPE(command, y, a);
  NEW(command_B_2, res);
  res->x = self->x;
  res->y = y;
  res->super.call = do_command_B_2;

  return COMMAND_RETURN(c, &res->super.super);
}

static int do_command_B(struct command *ignored UNUSED,
			struct lsh_object *a,
			struct command_continuation *c)
{
  NEW(command_B_1, res);
  CAST_SUBTYPE(command, x, a);
  res->x = x;
  res->super.call = do_command_B_1;

  return COMMAND_RETURN(c, &res->super.super);
}

struct command command_B = { STATIC_HEADER, do_command_B };

#if 0
/* xxCLASS:
   (class
     (name command_compose_continuation)
     (super command_continuation)
     (vars
       (f object command)
       (c object command_continuation)))
*/

static int do_continue_compose(struct command_continuation *c,
			       struct lsh_object *value)
{
  CAST(compose_continuation, self, c);
  return COMMAND_CALL(self->f, value, self->c);
}

static struct command_continuation *
make_compose_continuation(struct command *f, struct command_continuation *c)
{
  NEW(compose_continuation, self);
  self->f = f;
  self->c = c;

  return &self->super;
}

/* xxCLASS:
   (class
     (name command_compose)
     (super command)
     (vars
       (arg object command)
       (f object command)))
*/

int do_compose_call(struct command_continuation *c, lsh_object *value)
{
  CAST(command_compose, self, c);
  return COMMAND_CALL(self->arg,
		      make_compose_continuation(self->f, c));
}
#endif

/* Returned by listen */
/* CLASS:
   (class
     (name listen_value)
     (vars
       (fd . int)
       (peername string)
       (peerport . int)))
*/

/* CLASS:
   (class
     (name listen_command)
     (super command)
     (vars
       (backend object io_backend)
       (address . "struct sockaddr_in")))
*/

/* CLASS:
   (class
     (name listen_command_callback)
     (super fd_listen_callback)
     (vars
       (c object command_continuation)))
*/

static int do_listen_continue(struct fd_listen_callback *s, int fd,
			      size_t addr_len UNUSED,
			      struct sockaddr *peer UNUSED )
{
  CAST(listen_command_callback, self, s);
  NEW(listen_value, res);
  res->fd = fd;
  /* Parse peer addr */
  return COMMAND_RETURN(self->c, &res->super);
}

static struct fd_listen_callback *
make_listen_command_callback(struct command_continuation *c)
{
  NEW(listen_command_callback, closure);
  closure->c = c;
  closure->super.f = do_listen_continue;
  
  return &closure->super;
}

static int do_listen_call(struct command *s,
			  struct lsh_object *arg,
			  struct command_continuation *c)		  
{
  CAST(listen_command, self, s);
  CAST(ssh_connection, connection, arg);
  struct listen_fd *fd = io_listen(self->backend,
				   &self->address,
				   make_listen_command_callback(c));

  if (!fd)
    COMMAND_RETURN(c, NULL);
  
  REMEMBER_RESOURCE(connection->resources,
		    &fd->super.super);

  return LSH_OK | LSH_GOON;
}

struct command *make_listen_command(struct io_backend *backend,
				    struct lsh_string *interface,
				    UINT32 port)
{
  NEW(listen_command, self);
  self->backend = backend;
  if (!tcp_addr(&self->address,
		interface->length,
		interface->data,
		port))
    {
      KILL(self);
      return NULL;
    }
  self->super.call = do_listen_call;

  return &self->super;
}
  
  
       
