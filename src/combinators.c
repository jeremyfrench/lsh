/* combinators.c
 *
 * Builtin combinator functions (S, K, ...)
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
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "combinators.c.x"

/* Combinators */

/* Ix == x */
DEFINE_COMMAND(command_I)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  COMMAND_RETURN(c, a);
}


/* ((K x) y) == x */
DEFINE_COMMAND2(command_K)
     (struct lsh_object *x,
      struct lsh_object *y UNUSED,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  COMMAND_RETURN(c, x);
}
      

/* ((S f) g)x == (f x)(g x) */

/* Represents ((S f) g) */
/* GABA:
   (class
     (name command_S_2)
     (super command_simple)
     (vars
       (f object command)
       (g object command)))
*/

/* Receives the value of (f x) */
/* GABA:
   (class
     (name command_S_continuation)
     (super command_frame)
     (vars
       (g object command)
       (x object lsh_object)))
*/

static void
do_command_S_continuation(struct command_continuation *c,
			  struct lsh_object *value)
{
  CAST(command_S_continuation, self, c);
  CAST_SUBTYPE(command, op, value);
  COMMAND_CALL(self->g, self->x,
	       make_apply(op, self->super.up, self->super.e),
	       self->super.e);
}

static struct command_continuation *
make_command_S_continuation(struct command *g,
			    struct lsh_object *x,
			    struct command_continuation *up,
			    struct exception_handler *e)
{
  NEW(command_S_continuation, c);
  c->g = g;
  c->x = x;
  c->super.up = up;
  c->super.e = e;
  c->super.super.c = do_command_S_continuation;

  return &c->super.super;
}

DEFINE_COMMAND3(command_S)
     (struct lsh_object *f,
      struct lsh_object *g,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);

  COMMAND_CALL(cf, x,
	       make_command_S_continuation(cg, x, c, e),
	       e);
}

/* S' k f g x == k (f x) (g x) */

DEFINE_COMMAND4(command_Sp)
     (struct lsh_object *k,
      struct lsh_object *f,
      struct lsh_object *g,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, ck, k);
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);

  trace("command_Sp\n");
  
  COMMAND_CALL(cf, x,
	       make_apply(ck,
			  make_command_S_continuation(cg,
						      x, c, e),
			  e),
	       e);
}

/* B f g x == f (g x) */
DEFINE_COMMAND3(command_B)
     (struct lsh_object *f,
      struct lsh_object *g,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);

  trace("command_B, f = %xi, cf = %xi, g = %xi, cg = %xi\n",
        f, cf, g, cg);
  
  COMMAND_CALL(cg, x,
	       make_apply(cf, c, e), e);
}


/* B' k f g x == k (f (g x)) */
DEFINE_COMMAND4(command_Bp)
     (struct lsh_object *k,
      struct lsh_object *f,
      struct lsh_object *g,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, ck, k);
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);

  trace("command_Bp\n");

  COMMAND_CALL(cg, x,
	       make_apply(cf,
			  make_apply(ck, c, e), e),
	       e);
}

/* ((C f) y) x == (f x) y  */

/* GABA:
   (class
     (name command_C_continuation)
     (super command_frame)
     (vars
       (y object lsh_object)))
*/

static void
do_command_C_continuation(struct command_continuation *c,
			  struct lsh_object *value)
{
  CAST(command_C_continuation, self, c);
  CAST_SUBTYPE(command, op, value);
  
  COMMAND_CALL(op, self->y, self->super.up, self->super.e);
}

static struct command_continuation *
make_command_C_continuation(struct lsh_object *y,
			    struct command_continuation *up,
			    struct exception_handler *e)
{
  NEW(command_C_continuation, c);
  c->y = y;
  c->super.up = up;
  c->super.e = e;
  c->super.super.c = do_command_C_continuation;
  
  return &c->super.super;
}

DEFINE_COMMAND3(command_C)
     (struct lsh_object *f,
      struct lsh_object *y,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, cf, f);

  trace("command_C\n");

  COMMAND_CALL(cf, x,
	       make_command_C_continuation(y, c, e),
	       e);
}

/* FIXME: Move this function somewhere else. It should also be used by
 * do_trace_continuation. */
static const char *
describe_object(struct lsh_object *x)
{
  if (!x)
    return "<NULL>";
  if (!x->isa)
    return "<STATIC>";

  return x->isa->name;
}

#if 1
/* C' k f y x == k (f x) y */
DEFINE_COMMAND4(command_Cp)
     (struct lsh_object *k,
      struct lsh_object *f,
      struct lsh_object *y,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, ck, k);
  CAST_SUBTYPE(command, cf, f);

  trace("command_Cp\n");
  werror("command_Cp: k: %z, f: %z, y: %z, x: %z\n",
	 describe_object(k),
	 describe_object(f),
	 describe_object(y),
	 describe_object(x));
  
  COMMAND_CALL(cf, x,
	       make_apply(ck,
			  make_command_C_continuation(y, c, e), e),
	       e);
}
#else

/* C' c f y x == c (f x) y */

/* Represents (C' c f y x) */
/* GABA:
   (class
     (name command_Cp_3)
     (super command_simple)
     (vars
       (c object command)
       (f object command)
       (y object lsh_object)))
*/

static void
do_command_Cp_3(struct command *s,
		struct lsh_object *x,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(command_Cp_3, self, s);

  werror("do_command_Cp_3: k: %z, f: %z, y: %z, x: %z\n",
	 describe_object(&self->c->super),
	 describe_object(&self->f->super),
	 describe_object(self->y),
	 describe_object(x));
  
  COMMAND_CALL(self->f, x,
	       make_apply(self->c,
			  make_command_C_continuation(self->y, c, e), e),
	       e);
}

static struct lsh_object *
do_simple_command_Cp_3(struct command_simple *s,
		      struct lsh_object *x)
{
  CAST(command_Cp_3, self, s);
  CAST_SUBTYPE(command_simple, cs, self->c);
  CAST_SUBTYPE(command_simple, fs, self->f);
  CAST_SUBTYPE(command_simple, op, COMMAND_SIMPLE_CALL(cs, COMMAND_SIMPLE_CALL(fs, x)));
  return COMMAND_SIMPLE_CALL(op, self->y);
}

struct command *
make_command_Cp_3(struct command *c,
		  struct command *f,
		  struct lsh_object *y)
{
  NEW(command_Cp_3, res);
  res->c = c;
  res->f = f;
  res->y = y;
  res->super.super.call = do_command_Cp_3;
  res->super.call_simple = do_simple_command_Cp_3;

  return &res->super.super;
}

struct lsh_object *
collect_Cp_3(struct collect_info_3 *info UNUSED,
	     struct lsh_object *c,
	     struct lsh_object *f,
	     struct lsh_object *y)
{
  CAST_SUBTYPE(command, cc, c);
  CAST_SUBTYPE(command, cf, f);

  return &make_command_Cp_3(cc, cf, y)->super;
}

struct collect_info_3 collect_info_Cp_3 =
STATIC_COLLECT_3_FINAL(collect_Cp_3);

struct collect_info_2 collect_info_Cp_2 =
STATIC_COLLECT_2(&collect_info_Cp_3);

struct collect_info_1 command_Cp =
STATIC_COLLECT_1(&collect_info_Cp_2);

#endif
