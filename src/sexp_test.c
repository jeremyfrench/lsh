/* sexp_test.c
 *
 * Reads sexp on stdin, and writes them out again on stdout.
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

#include "format.h"
#include "io.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sexp_test.c.x"

static void
do_sexp_test_handler(struct exception_handler *s UNUSED,
		     struct exception *e)
{
  werror("sexp_test: %z\n", e->msg);

  /* FIXME: It would be better to set the exit_success variable. */
  exit(EXIT_FAILURE);
}

static struct exception_handler handler =
STATIC_EXCEPTION_HANDLER(do_sexp_test_handler, NULL);

/* GABA:
   (class
     (name output_sexp)
     (super sexp_handler)
     (vars
       (write object abstract_write)
       (style . int)))
*/

static int do_output_sexp(struct sexp_handler *h, struct sexp *e)
{
  CAST(output_sexp, closure, h);
  A_WRITE(closure->write, sexp_format(e, closure->style, 0),
	  &handler);

  A_WRITE(closure->write, ssh_format("\n"), &handler);
  
  return 0;
}

/* GABA:
   (class
     (name input_closed)
     (super close_callback)
     (vars
       (status . "int *")
       (output object write_buffer)))
*/

static int do_close(struct close_callback *c, int reason)
{
  CAST(input_closed, closure, c);

  write_buffer_close(closure->output);  

  *closure->status = (reason == CLOSE_EOF) ? EXIT_SUCCESS : EXIT_FAILURE;

  return 4711;
}

#define BLOCK_SIZE 2000

int main(int argc UNUSED, char **argv UNUSED)
{
  NEW(io_backend, backend);
  NEW(output_sexp, out);
  NEW(input_closed, close);
  struct write_buffer *write;

  int status = 17;
  
  init_backend(backend);

  write = io_write(make_io_fd(backend, STDOUT_FILENO),
		   BLOCK_SIZE, NULL)->buffer;

  out->super.handler = do_output_sexp;
  out->write = &write->super;
  out->style = SEXP_ADVANCED;
  
  close->super.f = do_close;
  close->output = write;
  close->status = &status;
  
  io_read(make_io_fd(backend, STDIN_FILENO),
	  make_read_sexp(&out->super, BLOCK_SIZE, SEXP_TRANSPORT, 1),
	  &close->super);

  io_run(backend);

  return status;
}
	  
  
  
