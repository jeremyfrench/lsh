/* sexp_conv.c
 *
 * Reads a sexp in given form from, and writes it in given form.
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

#include "io.h"
#include "lsh.h"
#include "lsh_argp.h"
#include "sexp_commands.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>
#include <unistd.h>

#include "sexp_conv.c.x"

/* Global, for simplicity */
int exit_code = EXIT_SUCCESS;

/* GABA:
   (expr
     (name make_sexp_conv)
     (params
       (read object command)
       (write object command))
       ;; (dest object abstract_write))
     (expr
       (lambda (in)
         (write (read in)))))
*/


static void
do_exc_sexp_conv_handler(struct exception_handler *self,
			 const struct exception *x)
{
  /* CAST(exc_sexp_conv_handler, self, s); */
  
  switch (x->type)
    {
    case EXC_SEXP_SYNTAX:
      werror("Invalid SEXP input.\n");
      exit_code = EXIT_FAILURE;
      /* Fall through */
    case EXC_SEXP_EOF:
      /* Normal termination */
      EXCEPTION_RAISE(self->parent, &finish_read_exception);
      break;
    case EXC_IO_WRITE:
    case EXC_IO_READ:
      {
	CAST(io_exception, e, x);
	exit_code = EXIT_FAILURE;
	werror("sexp_conv: %z, (errno = %i)\n", x->msg, e->error);
	break;
      }
    default:
      exit_code = EXIT_FAILURE;
      EXCEPTION_RAISE(self->parent, x);
      return;
    }
}

/* Option parsing */

static const struct argp_child
sub_parsers[] =
{
  { &sexp_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg UNUSED, struct argp_state *state UNUSED)
{
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = state->input;
      state->child_inputs[1] = NULL;
      break;
    }
  return 0;
}

static const struct argp
main_argp =
{ NULL, main_argp_parser, NULL,
  "Reads an s-expression on stdin, and outputs the same "
  "s-expression on stdout, possibly using a different "
  "encoding. By default, output uses the advanced encoding. ",
  sub_parsers,
  NULL
};
  

#define SEXP_BUFFER_SIZE 1024

int main(int argc, char **argv)
{
  int input_format = SEXP_TRANSPORT;
  sexp_argp_input output_format = SEXP_ADVANCED;

  struct exception_handler *e;
  NEW(io_backend, backend);

  argp_parse(&main_argp, argc, argv, 0, NULL, &output_format);

  init_backend(backend);

  /* Patch the parent pointer later */
  e = make_exception_handler(do_exc_sexp_conv_handler,
			     NULL, HANDLER_CONTEXT);
  
  {
    CAST_SUBTYPE(command, work,
		 make_sexp_conv(
		   make_read_sexp_command(input_format, 1),
		   make_print_sexp_to(output_format,
				      &(io_write(make_io_fd(backend,
							    STDOUT_FILENO,
							    e),
						 SEXP_BUFFER_SIZE,
						 NULL)
					->write_buffer->super))));

    struct io_fd *in = make_io_fd(backend, STDIN_FILENO, e);

    /* Fixing the exception handler creates a circularity */
    e->parent = make_exc_finish_read_handler(&in->super, &default_exception_handler);
    
    COMMAND_CALL(work, in,
		 &discard_continuation, e);
  }
  io_run(backend);

  return exit_code;
}
