/* sexp_commands.c
 *
 * Reading and writing of s-expressions.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balazs Scheidler, Niels Möller
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

#include "sexp_commands.h"

#include "format.h"
#include "xalloc.h"

#include "sexp_commands.c.x"

/* (write out sexp)
 *
 * Returns the sexp. */

/* GABA:
   (class
     (name write_sexp_command)
     (super command)
     (vars
       (format . int)
       (dest object abstract_write)))
*/

static void
do_write_sexp(struct command *s,
	      struct lsh_object *a,
	      struct command_continuation *c,
	      struct exception_handler *e UNUSED)
{
  CAST(write_sexp_command, self, s);
  CAST_SUBTYPE(sexp, o, a);

  A_WRITE(self->dest, sexp_format(o, self->format, 0));
  if (self->format != SEXP_CANONICAL)
    A_WRITE(self->dest, ssh_format("\n"));

  COMMAND_RETURN(c, a);
}

struct command *
make_write_sexp_to(int format, struct abstract_write *dest)
{
  NEW(write_sexp_command, self);
  self->super.call = do_write_sexp;
  self->format = format;
  self->dest = dest;

  return &self->super;
}

/* GABA:
   (class
     (name write_sexp_collect)
     (super command_simple)
     (vars
       (format . int)))
*/

static struct lsh_object *
do_write_sexp_collect(struct command_simple *s,
		      struct lsh_object *a)
{
  CAST(write_sexp_collect, self, s);
  CAST_SUBTYPE(abstract_write, dest, a);

  return &make_write_sexp_to(self->format, dest)->super;
}

struct command_simple *
make_write_sexp_command(int format)
{
  NEW(write_sexp_collect, self);
  self->super.super.call = do_call_simple_command;
  self->super.call_simple = do_write_sexp_collect;
  self->format = format;

  return &self->super;
}

/* GABA:
   (class
     (name read_sexp_command)
     (super command)
     (vars
       (format . int)
       (goon . int)))
*/

#define SEXP_BUFFER_SIZE 1024

static void
do_read_sexp(struct command *s,
	     struct lsh_object *a,
	     struct command_continuation *c,
	     struct exception_handler *e)
{
  CAST(read_sexp_command, self, s);
  CAST_SUBTYPE(io_fd, fd, a);

  io_read(fd,
	  make_buffered_read(SEXP_BUFFER_SIZE,
			     make_read_sexp(self->format, self->goon, c, e)),
	  NULL);
}

struct command *
make_read_sexp_command(int format, int goon)
{
  NEW(read_sexp_command, self);
  self->super.call = do_read_sexp;
  self->format = format;
  self->goon = goon;

  return &self->super;
}
