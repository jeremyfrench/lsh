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

/* CLASS:
   (class
     (name compose_continuation)
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

/* CLASS:
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

