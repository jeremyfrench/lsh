/* sexpconv.c
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
#include "sexp_commands.h"
#include "werror.h"
#include "xalloc.h"

#include "getopt.h"

#include <string.h>
#include <unistd.h>

#include "sexp_conv.c.x"

/* Global, for simplicity */
int exit_code = EXIT_SUCCESS;

struct sexp_format
{
  char *name;
  int id;
};

static const struct sexp_format sexp_formats[] = {
  { "transport", SEXP_TRANSPORT },
  { "canonical", SEXP_CANONICAL },
  { "advanced", SEXP_ADVANCED },
  { "international", SEXP_INTERNATIONAL },
  { NULL, 0 }
};

static void list_formats(void)
{
  int i;

  werror("Available formats are:\n");
  for (i = 0; sexp_formats[i].name; i++)
    werror("  %z\n", sexp_formats[i].name);
}

static int lookup_sexp_format(const char *name)
{
  int i;

  for (i = 0; sexp_formats[i].name; i++)
    {
      if (strcasecmp(sexp_formats[i].name, name) == 0)
	return sexp_formats[i].id;
    }
  return -1;
}

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
do_exc_sexp_conv_io_handler(struct exception_handler *self,
			    const struct exception *x)
{
  if (x->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, e, x);

      switch(x->type)
	{
	case EXC_IO_EOF:
	  close_fd_nicely(e->fd, 0);
	  break;
	case EXC_IO_READ:
	case EXC_IO_WRITE:
	  if (e->fd)
	    close_fd(e->fd, 0);
	  exit_code = EXIT_FAILURE;
	  break;
	default:
	  exit_code = EXIT_FAILURE;
	  EXCEPTION_RAISE(self->parent, x);
	  return;
	}
      werror("lsh: %z, (errno = %i)\n", x->msg, e->error);
    }
  else
    EXCEPTION_RAISE(self->parent, x);
}

static struct exception_handler exc_io_handler
= STATIC_EXCEPTION_HANDLER(do_exc_sexp_conv_io_handler, &default_exception_handler);

/* GABA:
   (class
     (name exc_sexp_conv_handler)
     (super exception_handler)
     (vars
       (in object io_fd)))
*/

static void
do_exc_sexp_conv_handler(struct exception_handler *s,
			 const struct exception *x)
{
  CAST(exc_sexp_conv_handler, self, s);
  
  switch (x->type)
    {
    case EXC_SEXP_SYNTAX:
      werror("Invalid SEXP input.\n");
      exit_code = EXIT_FAILURE;
      break;
    case EXC_SEXP_EOF:
      /* Normal termination */
      break;
    default:
      exit_code = EXIT_FAILURE;
      EXCEPTION_RAISE(self->super.parent, x);
      return;
    }
  close_fd(&self->in->super, 0);
}

static struct exception_handler *
make_exc_sexp_conv_handler(struct io_fd *in)
{
  NEW(exc_sexp_conv_handler, self);
  self->super.raise = do_exc_sexp_conv_handler;
  self->super.parent = &default_exception_handler;
  self->in = in;

  return &self->super;
}

#define SEXP_BUFFER_SIZE 1024

int main(int argc, char **argv)
{
  int option;
  int input_format = SEXP_ADVANCED; 
  int output_format = SEXP_ADVANCED;

  NEW(io_backend, backend);

  for (;;)
    {
      static const struct option options[] =
      {
	{ "verbose", no_argument, NULL, 'v' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "debug", no_argument, &debug_flag, 1},
	{ "input", required_argument, NULL, 'i'},
	{ "output", required_argument, NULL, 'o'},
	{ NULL }
      };
      
      option = getopt_long(argc, argv, "qvi:o:", options, NULL);
      switch(option)
	{
	case -1:
	  goto options_done;
	  
	case 'q':
	  quiet_flag = 1;
	  break;

	case 'v':
	  verbose_flag = 1;
	  break;
	  
	case 'i':
	  /* specify input format */
	  input_format = lookup_sexp_format(optarg);
	  if (input_format < 0)
	    {
	      werror("Invalid input format.\n");
	      list_formats();
	      return EXIT_FAILURE;
	    }
	  break;

	case 'o':
	  /* specify output format */
	  output_format = lookup_sexp_format(optarg);
	  if (output_format < 0)
	    {
	      werror("Invalid output format.\n");
	      list_formats();
	      return EXIT_FAILURE;
	    }
	  break;
	}
    }

 options_done:
  
  init_backend(backend);

  {
    CAST_SUBTYPE(command, work,
		 make_sexp_conv(
		   make_read_sexp_command(input_format, 1),
		   make_write_sexp_to(output_format,
				      &(io_write(make_io_fd(backend,
							    STDOUT_FILENO,
							    &exc_io_handler),
						 SEXP_BUFFER_SIZE,
						 NULL)
					->write_buffer->super))));

    struct io_fd *in = make_io_fd(backend, STDIN_FILENO, &exc_io_handler);
      
    COMMAND_CALL(work, in,
		 &discard_continuation,
		 make_exc_sexp_conv_handler(in));
  }
  io_run(backend);

  return exit_code;
}
