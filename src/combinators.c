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

#include <assert.h>

/* Combinators */

/* Ix == x */

static struct lsh_object *
do_simple_command_I(struct command_simple *ignored UNUSED,
		    struct lsh_object *arg)
{
  return arg;
}

struct command_simple command_I =
STATIC_COMMAND_SIMPLE(do_simple_command_I);

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
  NEW(command_K_1, res);
  res->x = x;
  res->super.super.call = do_call_simple_command;
  res->super.call_simple = do_simple_command_K_1;

  return &res->super.super;
}

static struct lsh_object *
do_simple_command_K(struct command_simple *ignored UNUSED,
		    struct lsh_object *a)
{
  return &make_command_K_1(a)->super;
}

struct command_simple command_K = STATIC_COMMAND_SIMPLE(do_simple_command_K);

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

static struct lsh_object *collect_S_2(struct collect_info_2 *info,
				      struct lsh_object *f,
				      struct lsh_object *g)
{
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);
  assert(!info);
  
  return &make_command_S_2(cf, cg)->super;
}

struct collect_info_2 collect_info_S_2 =
STATIC_COLLECT_2_FINAL(collect_S_2);

struct collect_info_1 command_S =
STATIC_COLLECT_1(&collect_info_S_2);

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

static struct lsh_object *collect_B_2(struct collect_info_2 *info,
				      struct lsh_object *f,
				      struct lsh_object *g)
{
  CAST_SUBTYPE(command, cf, f);
  CAST_SUBTYPE(command, cg, g);
  assert(!info);
  
  return &make_command_B_2(cf, cg)->super;
}

struct collect_info_2 collect_info_B_2 =
STATIC_COLLECT_2_FINAL(collect_B_2);

struct collect_info_1 command_B =
STATIC_COLLECT_1(&collect_info_B_2);

/* ((C f) y) x == (f x) y  */

/* Represents ((C f) g) */
/* GABA:
   (class
     (name command_C_2)
     (super command_simple)
     (vars
       (f object command)
       (y object command)))
*/

/* GABA:
   (class
     (name command_S_continuation)
     (super command_frame)
     (vars
       (y object lsh_object)))
*/

static int do_command_B_continuation(struct command_continuation *c,
				     struct lsh_object *value)
{
  CAST(command_B_continuation, self, c);
  CAST_SUBTYPE(command, op, value);
  return COMMAND_CALL(op, self->y, self->super.up);
}

static int do_command_C_2(struct command *s,
			  struct lsh_object *x,
			  struct command_continuation *up)
{
  CAST(command_C_2, self, s);
  NEW(command_C_continuation, c);
  c->y = self->y;
  c->super.up = up;
  return COMMAND_CALL(self->f, x, c);
}

static struct lsh_object *do_simple_command_C_2(struct command_simple *s,
						struct lsh_object *x)
{
  CAST(command_C_2, self, s);
  CAST_SUBTYPE(command_simple, f, self->f);
  CAST_SUBTYPE(command_simple, v, COMMAND_SIMPLE(f, x));
  return COMMAND_SIMPLE(v, self->y);
}

static struct command *
make_command_C_2(struct command *f,
		 struct lsh_object *y)
{
  NEW(command_C_2, res);
  res->f = f;
  res->y = y;
  res->super.super.call = do_command_C_2;
  res->super.call_simple = do_simple_command_C_2;

  return &res->super.super;
}

static struct lsh_object *collect_C_2(struct collect_info_2 *info,
				      struct lsh_object *f,
				      struct lsh_object *y)
{
  CAST_SUBTYPE(command, cf, f);
  assert(!info);
  
  return &make_command_B_2(cf, y)->super;
}

struct collect_info_2 collect_info_C_2 =
STATIC_COLLECT_2_FINAL(collect_C_2);

struct collect_info_1 command_C =
STATIC_COLLECT_1(&collect_info_C_2);

