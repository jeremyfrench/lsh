/* command.c
 *
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "command.h"

#include "io.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "command.h.x"
#undef GABA_DEFINE

#include "command.c.x"

static void
do_discard_continuation(struct command_continuation *ignored UNUSED,
			struct lsh_object *x UNUSED)
{}

struct command_continuation discard_continuation =
{ STATIC_HEADER, do_discard_continuation};

struct command_context *
make_command_context(struct command_continuation *c,
		     struct exception_handler *e)
{
  NEW(command_context, self);
  self->c = c;
  self->e = e;

  return self;
}

/* A command taking 2 arguments */
/* GABA:
   (class
     (name command_2_invoke)
     (super command)
     (vars
       (f object command_2)
       (a1 object lsh_object)))
*/

static void
do_command_2_invoke(struct command *s, struct lsh_object *a2,
		    struct command_continuation *c,
		    struct exception_handler *e)
{
  CAST(command_2_invoke, self, s);
  self->f->invoke(self->a1, a2, c, e);
}

struct command *
make_command_2_invoke(struct command_2 *f,
		      struct lsh_object *a1)
{
  NEW(command_2_invoke, self);

  self->super.call = do_command_2_invoke;
  self->f = f;
  self->a1 = a1;

  return &self->super;
}

void
do_command_2(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(command_2, self, s);
  COMMAND_RETURN(c, make_command_2_invoke(self, a1));
}

/* A command taking 3 arguments */
/* GABA:
   (class
     (name command_3_invoke_2)
     (super command)
     (vars
       (f object command_3)
       (a1 object lsh_object)
       (a2 object lsh_object)))
*/

static void
do_command_3_invoke_2(struct command *s,
		      struct lsh_object *a3,
		      struct command_continuation *c,
		      struct exception_handler *e)
{
  CAST(command_3_invoke_2, self, s);
  self->f->invoke(self->a1, self->a2, a3, c, e);
}

struct command *
make_command_3_invoke_2(struct command_3 *f,
			struct lsh_object *a1,
			struct lsh_object *a2)
{
  NEW(command_3_invoke_2, self);

  self->super.call = do_command_3_invoke_2;
  self->f = f;
  self->a1 = a1;
  self->a2 = a2;

  return &self->super;
}

/* GABA:
   (class
     (name command_3_invoke)
     (super command)
     (vars
       (f object command_3)
       (a1 object lsh_object)))
*/

static void
do_command_3_invoke(struct command *s,
		    struct lsh_object *a2,
		    struct command_continuation *c,
		    struct exception_handler *e UNUSED)
{
  CAST(command_3_invoke, self, s);
  COMMAND_RETURN(c, make_command_3_invoke_2(self->f, self->a1, a2));
}

struct command *
make_command_3_invoke(struct command_3 *f,
		      struct lsh_object *a1)
{
  NEW(command_3_invoke, self);

  self->super.call = do_command_3_invoke;
  self->f = f;
  self->a1 = a1;

  return &self->super;
}

void
do_command_3(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(command_3, self, s);
  COMMAND_RETURN(c, make_command_3_invoke(self, a1));
}


/* A command taking 4 arguments */
/* GABA:
   (class
     (name command_4_invoke_3)
     (super command)
     (vars
       (f object command_4)
       (a1 object lsh_object)
       (a2 object lsh_object)
       (a3 object lsh_object)))
*/

static void
do_command_4_invoke_3(struct command *s,
		      struct lsh_object *a4,
		      struct command_continuation *c,
		      struct exception_handler *e)
{
  CAST(command_4_invoke_3, self, s);
  self->f->invoke(self->a1, self->a2, self->a3, a4, c, e);
}

struct command *
make_command_4_invoke_3(struct command_4 *f,
			struct lsh_object *a1,
			struct lsh_object *a2,
			struct lsh_object *a3)
{
  NEW(command_4_invoke_3, self);

  self->super.call = do_command_4_invoke_3;
  self->f = f;
  self->a1 = a1;
  self->a2 = a2;
  self->a3 = a3;

  return &self->super;
}

/* GABA:
   (class
     (name command_4_invoke_2)
     (super command)
     (vars
       (f object command_4)
       (a1 object lsh_object)
       (a2 object lsh_object)))
*/

static void
do_command_4_invoke_2(struct command *s,
		      struct lsh_object *a3,
		      struct command_continuation *c,
		      struct exception_handler *e UNUSED)
{
  CAST(command_4_invoke_2, self, s);
  COMMAND_RETURN(c, make_command_4_invoke_3(self->f, self->a1, self->a2, a3));
}

struct command *
make_command_4_invoke_2(struct command_4 *f,
			struct lsh_object *a1,
			struct lsh_object *a2)
{
  NEW(command_4_invoke_2, self);

  self->super.call = do_command_4_invoke_2;
  self->f = f;
  self->a1 = a1;
  self->a2 = a2;

  return &self->super;
}


/* GABA:
   (class
     (name command_4_invoke)
     (super command)
     (vars
       (f object command_4)
       (a1 object lsh_object)))
*/

static void
do_command_4_invoke(struct command *s,
		    struct lsh_object *a2,
		    struct command_continuation *c,
		    struct exception_handler *e UNUSED)
{
  CAST(command_4_invoke, self, s);
  COMMAND_RETURN(c, make_command_4_invoke_2(self->f, self->a1, a2));
}

struct command *
make_command_4_invoke(struct command_4 *f,
		      struct lsh_object *a1)
{
  NEW(command_4_invoke, self);

  self->super.call = do_command_4_invoke;
  self->f = f;
  self->a1 = a1;

  return &self->super;
}

void
do_command_4(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(command_4, self, s);
  COMMAND_RETURN(c, make_command_4_invoke(self, a1));
}


/* Tracing */

#if DEBUG_TRACE

/* GABA:
   (class
     (name trace_continuation)
     (super command_continuation)
     (vars
       (name . "const char *")
       (real object command_continuation)))
*/

static void
do_trace_continuation(struct command_continuation *s,
		      struct lsh_object *x)
{
  CAST(trace_continuation, self, s);

  trace("Leaving %z, value of type %t.\n",
	self->name, x);
  COMMAND_RETURN(self->real, x);
}

static struct command_continuation *
make_trace_continuation(const char *name,
			struct command_continuation *real)
{
  NEW(trace_continuation, self);
  self->super.c = do_trace_continuation;
  self->name = name;
  self->real = real;

  return &self->super;
}

/* GABA:
   (class
     (name trace_command)
     (super command)
     (vars
       (name . "const char *")
       (real object command)))
*/

static void
do_trace_command(struct command *s,
		 struct lsh_object *x,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  CAST(trace_command, self, s);

  trace("Entering %z\n", self->name);
#if 1
  COMMAND_CALL(self->real, x,
	       make_trace_continuation(self->name, c),
	       e);
#else
  COMMAND_CALL(self->real, x, c, e);
#endif
}

struct command *make_trace(const char *name, struct command *real)
{
  NEW(trace_command, self);
  self->super.call = do_trace_command;
  self->name = name;
  self->real = real;

  return &self->super;
}

struct lsh_object *collect_trace(const char *name, struct lsh_object *c)
{
  CAST_SUBTYPE(command, real, c);
  return &make_trace(name, real)->super;
}
#endif /* DEBUG_TRACE */
