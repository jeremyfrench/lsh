/* sexp_conv.c
 *
 * Reads a sexp in given form from, and writes it in given form.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler, Niels Möller
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

#include "algorithms.h"
#include "alist.h"
#include "atoms.h"
#include "crypto.h"
#include "io.h"
#include "lsh.h"
#include "lsh_argp.h"
#include "sexp_commands.h"
#include "spki.h"
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
       (transform object command)
       (print object command)
       (dest object abstract_write))
     (expr
       (lambda (in)
         (print dest (transform (read in))))))
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

#define OPT_HASH 0x200
#define OPT_SPKI_HASH 0x201
#define OPT_RAW_HASH 0x202
#define OPT_ONCE 0x203

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "spki-hash", OPT_SPKI_HASH, NULL, 0, "Output an SPKI hash for the object.", 0 },
  { "raw-hash", OPT_RAW_HASH, NULL, 0, "Output the hash for the canonical "
    "representation of the object, in hexadecimal.", 0 },
  { "hash", OPT_HASH, "Algorithm", 0, "Hash algorithm (default sha1).", 0 },
  { "once", OPT_ONCE, NULL, 0, "Process at most one s-expression.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

#define MODE_VANILLA 0
#define MODE_RAW_HASH 1
#define MODE_SPKI_HASH 2

/* GABA:
(class
  (name sexp_conv_options)
  (vars
    (input . sexp_argp_state)
    (output . sexp_argp_state)
    (once . int)
    (mode . int)
    (algorithms object alist)
    (hash . int)
    (transform object command)
    (print object command)
))
*/

static struct sexp_conv_options *make_options(void)
{
  NEW(sexp_conv_options, self);
  self->input = SEXP_TRANSPORT;
  self->output = SEXP_ADVANCED;
  self->once = 0;
  self->mode = MODE_VANILLA;
  self->transform = &command_I.super;
  self->algorithms = make_alist(2,
				ATOM_MD5, &md5_algorithm,
				ATOM_SHA1, &sha1_algorithm,
				-1);
  self->hash = ATOM_SHA1;

  return self;
}

static const struct argp_child
main_argp_children[] =
{
  { &sexp_input_argp, 0, NULL, 0 },
  { &sexp_output_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(sexp_conv_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->input;
      state->child_inputs[1] = &self->output;
      state->child_inputs[2] = NULL;
      break;
    case ARGP_KEY_END:
      {
	switch(self->mode)
	  {
	  default:
	    fatal("Internal error!");
	  case MODE_VANILLA:
	    self->transform = &command_I.super;
	    self->print = &make_sexp_print_command(self->output)->super;
	    break;
	  case MODE_SPKI_HASH:
	    {
	      CAST_SUBTYPE(hash_algorithm, a,
			   ALIST_GET(self->algorithms, self->hash));
	      self->transform = make_spki_hash(self->hash, a);
	      self->print = &make_sexp_print_command(self->output)->super;
	      break;
	    }
	  case MODE_RAW_HASH:
	    {
	      CAST_SUBTYPE(hash_algorithm, a,
			   ALIST_GET(self->algorithms, self->hash));
	      self->transform = &command_I.super;
	      self->print = make_sexp_print_raw_hash(a);
	      break;
	    }
	  }
	break;
      }
    case OPT_HASH:
      {
	int hash = lookup_hash(self->algorithms, arg, 0);
	if (hash)
	  self->hash = hash;
	else
	  argp_error(state, "Unknown hash algorithm '%s'.", arg);
	break;
      }
    case OPT_SPKI_HASH:
      self->mode = MODE_SPKI_HASH;
      break;
    case OPT_RAW_HASH:
      self->mode = MODE_RAW_HASH;
      break;
    case OPT_ONCE:
      self->once = 1;
      break;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, NULL,
  "Reads an s-expression on stdin, and outputs the same "
  "s-expression on stdout, possibly using a different "
  "encoding. By default, output uses the advanced encoding. ",
  main_argp_children,
  NULL, NULL
};
  

#define SEXP_BUFFER_SIZE 1024

int main(int argc, char **argv)
{
  struct sexp_conv_options *options = make_options();
  struct exception_handler *e;
  NEW(io_backend, backend);
  
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  init_backend(backend);

  /* Patch the parent pointer later */
  e = make_exception_handler(do_exc_sexp_conv_handler,
			     NULL, HANDLER_CONTEXT);
  
  {
    CAST_SUBTYPE(command, work,
		 make_sexp_conv(
		   make_read_sexp_command(options->input, !options->once),
		   options->transform,
		   options->print,
		   &(io_write(make_lsh_fd(backend,
					 STDOUT_FILENO,
					 e),
			      SEXP_BUFFER_SIZE,
			      NULL)
		     ->write_buffer->super)));

    struct lsh_fd *in = make_lsh_fd(backend, STDIN_FILENO, e);

    /* Fixing the exception handler creates a circularity */
    e->parent = make_exc_finish_read_handler(in,
					     &default_exception_handler,
					     HANDLER_CONTEXT);
    
    COMMAND_CALL(work, in,
		 &discard_continuation, e);
  }
  io_run(backend);

  return exit_code;
}
