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

#define GABA_DEFINE
#include "command.h.x"
#undef GABA_DEFINE

#include "command.c.x"

/* GABA:
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

struct lsh_object gaba_apply(struct lsh_object *f,
			     struct lsh_object *x)
{
  CAST_SUBTYPE(command_simple, cf, f);
  return COMMAND_SIMPLE(cf, x);
}

int do_call_simple_command(struct command *s,
			   struct lsh_object *arg,
			   struct command_continuation *c)
{
  CAST_SUBTYPE(command_simple, self, s);
  return COMMAND_RETURN(c, COMMAND_SIMPLE(self, arg));
}

/* Combinators */

/* Ix == x */

#if 0
static int do_command_I(struct command *ignored UNUSED,
			struct lsh_object *arg,
			struct command_continuation *c)			
{
  return COMMAND_RETURN(c, arg);
}
#endif

static struct lsh_object *
do_simple_command_I(struct command_simple *ignored UNUSED,
		    struct lsh_object *arg)
{
  return arg;
}

struct command_simple command_I =
STATIC_COMMAND_SIMPLE(do_simple_command_I);

/* ((S f) g)x == (f x)(g x) */

/* Continuation called after evaluating (f x) */
/* GABA:
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

/* Represents ((S f) g) */
/* GABA:
   (class
     (name command_S_2)
     (super command_simple)
     (vars
       (f object command)
       (g object command)))
*/

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

static struct lsh_object *
do_simple_command_S_2(struct command_simple *s,
		      struct lsh_object *x)
{
  CAST(command_S_2, self, s);
  CAST_SUBTYPE(command_simple, fs, self->f);
  CAST_SUBTYPE(command_simple, gs, self->g);
  CAST_SUBTYPE(command_simple, op, COMMAND_SIMPLE(fs, x));
  
  return COMMAND_SIMPLE(op, COMMAND_SIMPLE(gs, x));
}

struct command *make_command_S_2(struct command *f,
				 struct command *g)
{
  NEW(command_S_2, res);
  res->f = f;
  res->g = g;
  res->super.super.call = do_command_S_2;
  res->super.call_simple = do_simple_command_S_2;
  
  return &res->super.super;
}

struct lsh_object *
/* Represents (S f) */
/* GABA:
   (class
     (name command_S_1)
     (super command_simple)
     (vars
       (f object command)))
*/

static struct lsh_object *
do_simple_command_S_1(struct command_simple *s,
		      struct lsh_object *a)
{
  CAST(command_S_1, self, s);
  CAST_SUBTYPE(command, arg, a);

  return &make_command_S_2(self->f, arg)->super;
}

struct command *make_command_S_1(struct command *f)
{
  NEW(command_S_1, res);
  res->f = f;
  res->super.super.call = do_call_simple_command;
  res->super.call_simple = do_simple_command_S_1;

  return &res->super.super;
}

static struct lsh_object *
do_simple_command_S(struct command_simple *ignored UNUSED,
		    struct lsh_object *a)
{
  CAST_SUBTYPE(command, arg, a);
  return &make_command_S_1(arg)->super;
}

struct command_simple command_S = STATIC_COMMAND_SIMPLE(do_simple_command_S);

struct lsh_object *gaba_apply_S_1(struct lsh_object *f)
{
  CAST_SUBTYPE(command, cf, f);
  return &make_command_S_1(cf)->super;
}
  
struct lsh_object *gaba_apply_S_2(struct lsh_object *f,
				  struct lsh_object *g)
{
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);
  return &make_command_S_2(cf, cg)->super;
}

/* ((K x) y) == x */

/* Represents (K x) */
/* GABA:
   (class
     (name command_K_1)
     (super command_simple)
     (vars
       (x object lsh_object)))
*/

static struct lsh_object *
do_simple_command_K_1(struct command_simple *s,
		      struct lsh_object *ignored UNUSED)
{
  CAST(command_K_1, self, s);
  return self->x;
}

struct command *make_command_K_1(struct lsh_object *x)
{
  NEW(command_S_1, res);
  res->x = x;
  res->super.super.call = do_call_simple_command;
  res->super.call_simple = do_simple_command_K_1;

  return &res->super.super;
}

struct command_simple command_K = STATIC_COMMAND_SIMPLE(do_simple_command_K);

/* ((B f) g) x == (f (g x)) */

/* Represents ((B f) g) */
/* GABA:
   (class
     (name command_B_2)
     (super command_simple)
     (vars
       (f object command)
       (g object command)))
*/

static int do_command_B_2(struct command *s,
			  struct lsh_object *x,
			  struct command_continuation *c)
{
  CAST(command_B_2, self, s);
  return COMMAND_CALL(self->g, x, make_apply(self->f, c));
}

static struct lsh_object *do_simple_command_B_2(struct command_simple *s,
						struct lsh_object *x)
{
  CAST(command_B_2, self, s);
  CAST_SUBTYPE(command_simple, fs, self->f);
  CAST_SUBTYPE(command_simple, gs, self->g);
  return COMMAND_SIMPLE(fs, COMMAND_SIMPLE(gs, x));
}

static struct command *
make_command_B_2(struct command *f,
		 struct command *g)
{
  NEW(command_B_2, res);
  res->f = f;
  res->g = g;
  res->super.super.call = do_command_B_2;
  res->super.call_simple = do_simple_command_B_2;

  return &res->super.super;
}

/* Represents (B f) */
/* GABA:
   (class
     (name command_B_1)
     (super command_simple)
     (vars
       (f object command)))
*/

static struct lsh_object *
do_simple_command_B_1(struct command_simple *s,
		      struct lsh_object *a)
{
  CAST(command_B_1, self, s);
  CAST_SUBTYPE(command, g, a);

  return &make_command_B_2(self->f, g)->super;
}

static struct command *make_command_B_1(struct command *f)
{
  NEW(command_B_1, res);
  res->f = f;
  res->super.super.call = do_call_simple_command;
  res->super.call_simple = do_simple_command_B_1;

  return &res->super.super;
}

static struct lsh_object *
do_simple_command_B(struct command_simple *ignored UNUSED,
		    struct lsh_object *a)
{
  CAST_SUBTYPE(command, f, a);
  return &make_command_B_1(f)->super;
}

struct command_simple command_B = STATIC_COMMAND_SIMPLE(do_simple_command_B);

/* Returned by listen */
/* GABA:
   (class
     (name listen_value)
     (vars
       (fd . int)
       (peername string)
       (peerport . int)))
*/

/* GABA:
   (class
     (name listen_command)
     (super command)
     (vars
       (backend object io_backend)
       (address . "struct sockaddr_in")))
*/

/* GABA:
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
