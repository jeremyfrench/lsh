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

#define GABA_DEFINE
#include "sexp_commands.h.x"
#undef GABA_DEFINE

#include "sexp_commands.c.x"

/* (write out sexp)
 *
 * Prints the sexp to tha abstract_write OUT. Returns the sexp. */

/* GABA:
   (class
     (name print_sexp_to)
     (super command)
     (vars
       (format . int)
       (dest object abstract_write)))
*/

static void
do_print_sexp(struct command *s,
	      struct lsh_object *a,
	      struct command_continuation *c,
	      struct exception_handler *e UNUSED)
{
  CAST(print_sexp_to, self, s);
  CAST_SUBTYPE(sexp, o, a);

  A_WRITE(self->dest, sexp_format(o, self->format, 0));
  if (self->format != SEXP_CANONICAL)
    A_WRITE(self->dest, ssh_format("\n"));

  COMMAND_RETURN(c, a);
}

struct command *
make_print_sexp_to(int format, struct abstract_write *dest)
{
  NEW(print_sexp_to, self);
  self->super.call = do_print_sexp;
  self->format = format;
  self->dest = dest;

  return &self->super;
}

struct lsh_object *
do_print_sexp_simple(struct command_simple *s,
		     struct lsh_object *a)
{
  CAST(print_sexp_command, self, s);
  CAST_SUBTYPE(abstract_write, dest, a);

  return &make_print_sexp_to(self->format, dest)->super;
}

struct command_simple *
make_print_sexp_command(int format)
{
  NEW(print_sexp_command, self);
  self->super.super.call = do_call_simple_command;
  self->super.call_simple = do_print_sexp_simple;
  self->format = format;

  return &self->super;
}

/* Make sure that the fd is closed properly. */
/* GABA:
   (class
     (name read_sexp_continuation)
     (super command_continuation)
     (vars
       (fd object lsh_fd)
       (up object command_continuation)))
*/

static void
do_read_sexp_continue(struct command_continuation *s,
		      struct lsh_object *a)
{
  CAST(read_sexp_continuation, self, s);
  close_fd_nicely(self->fd, 0);

  COMMAND_RETURN(self->up, a);
}

static struct command_continuation*
make_read_sexp_continuation(struct io_fd *fd,
			    struct command_continuation *up)
{
  NEW(read_sexp_continuation, self);
  self->super.c =do_read_sexp_continue;
  self->fd = &fd->super;
  self->up = up;

  return &self->super;
}

/* GABA:
   (class
     (name read_sexp_exception_handler)
     (super exception_handler)
     (vars
       (fd object lsh_fd)))
*/

static void
do_read_sexp_exception_handler(struct exception_handler *s,
			       const struct exception *x)
{
  CAST(read_sexp_exception_handler, self, s);
  if (x->type & EXC_SEXP)
    close_fd_nicely(self->fd, 0);

  EXCEPTION_RAISE(self->super.parent, x);
}

static struct exception_handler *
make_read_sexp_exception_handler(struct io_fd *fd,
				 struct exception_handler *e)
{
  NEW(read_sexp_exception_handler, self);
  self->super.raise = do_read_sexp_exception_handler;
  self->super.parent = e;
  self->fd = &fd->super;

  return &self->super;
}

#define SEXP_BUFFER_SIZE 1024

void
do_read_sexp(struct command *s,
	     struct lsh_object *a,
	     struct command_continuation *c,
	     struct exception_handler *e)
{
  CAST(read_sexp_command, self, s);
  CAST_SUBTYPE(io_fd, fd, a);

  if (!self->goon)
    c = make_read_sexp_continuation(fd, c);
  
  io_read(fd,
	  make_buffered_read(SEXP_BUFFER_SIZE,
			     make_read_sexp(self->format, self->goon, c,
					    make_read_sexp_exception_handler(fd, e))),
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
