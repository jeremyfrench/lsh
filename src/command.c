/* command.c
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
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "command.h.x"
#undef GABA_DEFINE

#include "command.c.x"

static int
do_discard_continuation(struct command_continuation *ignored UNUSED,
			struct lsh_object *x UNUSED)
{
  return LSH_OK | LSH_GOON;
}

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
  return COMMAND_CALL(self->f, value,
		      self->super.up, self->super.e);
}

struct command_continuation *
make_apply(struct command *f,
	   struct command_continuation *c, struct exception_handler *e)
{
  NEW(command_apply, res);

  res->f = f;
  res->super.up = c;
  res->super.e = e;
  res->super.super.c = do_command_apply;

  return &res->super.super;
}

struct lsh_object *gaba_apply(struct lsh_object *f,
			      struct lsh_object *x)
{
  CAST_SUBTYPE(command_simple, cf, f);
  return COMMAND_SIMPLE(cf, x);
}

int do_call_simple_command(struct command *s,
			   struct lsh_object *arg,
			   struct command_continuation *c,
			   struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(command_simple, self, s);
  return COMMAND_RETURN(c, COMMAND_SIMPLE(self, arg));
}


/* Unimplemented command */
static int
do_command_unimplemented(struct command *s UNUSED,
			 struct lsh_object *o UNUSED,
			 struct command_continuation *c UNUSED,
			 struct exception_handler *e UNUSED)
{ fatal("command.c: Unimplemented command.\n"); }

static struct lsh_object *
do_command_simple_unimplemented(struct command_simple *s UNUSED,
				struct lsh_object *o UNUSED)
{ fatal("command.c: Unimplemented simple command.\n"); }

struct command_simple command_unimplemented =
{ { STATIC_HEADER, do_command_unimplemented}, do_command_simple_unimplemented};


/* Tracing
 *
 * For now, trace only function entry. */

/* GABA:
   (class
     (name trace_command)
     (super command)
     (vars
       (name . "const char *")
       (real object command)))
*/

static int do_trace_command(struct command *s,
			    struct lsh_object *x,
			    struct command_continuation *c,
			    struct exception_handler *e)
{
  CAST(trace_command, self, s);

  trace("Entering %z\n", self->name);
  return COMMAND_CALL(self->real, x, c, e);
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

#if 0
/* This command should be obsoleted by the exception mechanism */
/* Fail if NULL. This commands returns its argument unchanged. Unless
 * it is NULL, in which case it doesn't return at all, but instead
 * returns an LSH_FAIL status to the mainloop. */

static int
do_command_die_on_null(struct command *s UNUSED,
		       struct lsh_object *x,
		       struct command_continuation *c,
		       struct exception_handler *e)
{
  return x ? COMMAND_RETURN(c, x) : LSH_FAIL | LSH_DIE;
}

struct command command_die_on_null =
{ STATIC_HEADER, do_command_die_on_null};
#endif

/* Collecting arguments */
struct lsh_object *
do_collect_1(struct command_simple *s, struct lsh_object *a)
{
  CAST(collect_info_1, self, s);
  return self->f(self, a);
}

/* GABA:
   (class
     (name collect_state_1)
     (super command_simple)
     (vars
       (info object collect_info_2)
       (a object lsh_object)))
*/

/* GABA:
   (class
     (name collect_state_2)
     (super command_simple)
     (vars
       (info object collect_info_3)
       (a object lsh_object)
       (b object lsh_object)))
*/

/* GABA:
   (class
     (name collect_state_3)
     (super command_simple)
     (vars
       (info object collect_info_4)
       (a object lsh_object)
       (b object lsh_object)
       (c object lsh_object)))
*/

static struct lsh_object *
do_collect_2(struct command_simple *s,
	     struct lsh_object *x)
{
  CAST(collect_state_1, self, s);
  return self->info->f(self->info, self->a, x);
}

struct lsh_object *
make_collect_state_1(struct collect_info_1 *info,
		     struct lsh_object *a)
{
  NEW(collect_state_1, self);
  self->info = info->next;
  self->a = a;

  self->super.call_simple = do_collect_2;
  self->super.super.call = do_call_simple_command;
  
  return &self->super.super.super;
}

static struct lsh_object *
do_collect_3(struct command_simple *s,
	     struct lsh_object *x)
{
  CAST(collect_state_2, self, s);
  return self->info->f(self->info, self->a, self->b, x);
}

struct lsh_object *
make_collect_state_2(struct collect_info_2 *info,
		     struct lsh_object *a,
		     struct lsh_object *b)
{
  NEW(collect_state_2, self);
  self->info = info->next;
  self->a = a;
  self->b = b;
  
  self->super.call_simple = do_collect_3;
  self->super.super.call = do_call_simple_command;
  
  return &self->super.super.super;
}

static struct lsh_object *
do_collect_4(struct command_simple *s,
	     struct lsh_object *x)
{
  CAST(collect_state_3, self, s);
  return self->info->f(self->info, self->a, self->b, self->c, x);
}

struct lsh_object *
make_collect_state_3(struct collect_info_3 *info,
		     struct lsh_object *a,
		     struct lsh_object *b,
		     struct lsh_object *c)
{
  NEW(collect_state_3, self);
  self->info = info->next;
  self->a = a;
  self->b = b;
  self->c = c;
  
  self->super.call_simple = do_collect_4;
  self->super.super.call = do_call_simple_command;
  
  return &self->super.super.super;
}

/* GABA:
   (class
     (name parallell_progn)
     (super command)
     (vars
       (body object object_list)))
*/

static int do_parallell_progn(struct command *s,
			      struct lsh_object *x,
			      struct command_continuation *c,
			      struct exception_handler *e)
{
  CAST(parallell_progn, self, s);
  unsigned i;
  int res = 0;
  
  for (i=0; i < LIST_LENGTH(self->body) - 1; i++)
    {
      CAST_SUBTYPE(command, command, LIST(self->body)[i]);
      res |= COMMAND_CALL(command, x, &discard_continuation, e);
      if (LSH_CLOSEDP(res))
	return res;
    }
  {
    CAST_SUBTYPE(command, command, LIST(self->body)[i]);
    
    return res | COMMAND_CALL(command, x, c, e);
  }
}

struct command *make_parallell_progn(struct object_list *body)
{
  assert(LIST_LENGTH(body));
  {
    NEW(parallell_progn, self);
    self->body = body;
    self->super.call = do_parallell_progn;

    return &self->super;
  }
}

static struct lsh_object *do_progn(struct command_simple *s UNUSED,
				   struct lsh_object *x)
{
  CAST(object_list, body, x);
  return &make_parallell_progn(body)->super;
}

struct command_simple progn_command =
STATIC_COMMAND_SIMPLE(do_progn);

