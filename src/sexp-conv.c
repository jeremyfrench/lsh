/* sexp-conv.c
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
#include "format.h"
#include "io.h"
#include "lsh.h"
#include "lsh_argp.h"
#include "sexp.h"
#include "spki.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "sexp-conv.c.x"


enum sexp_select_ops { OP_CAR, OP_CDR, OP_RETURN_CAR };

static struct sexp *
process_select(struct int_list *select,
	       struct sexp *expr)
{
  struct sexp_iterator *i;
  unsigned j;

  if (sexp_atomp(expr))
    {
      werror("Attempt select in a non-list expression.\n");
      return NULL;
    }

  i = SEXP_ITER(expr);
  assert(i);
  
  for (j = 0; j < LIST_LENGTH(select); j++)
    switch (LIST(select)[j])
      {
      case OP_RETURN_CAR:
	expr = SEXP_GET(i);
	if (!expr)
	  {
	    werror("List exhausted while selecting.\n");
	    return NULL;
	  }
	return expr;
	
	break;

      case OP_CAR:
	expr = SEXP_GET(i);
	if (!expr)
	  {
	    werror("List exhausted while selecting.\n");
	    return NULL;
	  }

	if (sexp_atomp(expr))
	  {
	    werror("Attempt select in a non-list expression.\n");
	    return NULL;
	  }
	  
	i = SEXP_ITER(expr);
	assert(i);
	  
	break;
	  
      case OP_CDR:
	SEXP_NEXT(i);

	if (!SEXP_LEFT(i))
	  {
	    werror("List exhausted while selecting.\n");

	    return NULL;
	  }
	break;
      }
  
  fatal("process_select: Internal error!\n");
}

static struct int_list *
parse_select(const char *arg)
{
  unsigned len = strlen(arg);

  /* Check syntax */
  if ( (len >= 3)
       && (arg[0] == 'c')
       && (arg[1] == 'a')
       && (arg[len-1] == 'r'))
    {
      struct int_list *ops = alloc_int_list(len - 2);
      unsigned i;
      
      for (i = 0; i < len - 3; i++)
	switch(arg[len - i - 2])
	  {
	  case 'a':
	    LIST(ops)[i] = OP_CAR;
	    break;
	  case 'd':
	    LIST(ops)[i] = OP_CDR;
	    break;
	  default:
	    KILL(ops);
	    return NULL;
	  }

      LIST(ops)[i++] = OP_RETURN_CAR;
      assert (i == LIST_LENGTH(ops));

      return ops;
    }
  return NULL;
}

/* Option parsing */

const char *argp_program_version
= "sexp-conv-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define OPT_HASH 0x200
#define OPT_SPKI_HASH 0x201
#define OPT_RAW_HASH 0x202
#define OPT_ONCE 0x203
#define OPT_SELECT 0x204

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "spki-hash", OPT_SPKI_HASH, NULL, 0, "Output an SPKI hash for the object.", 0 },
  { "raw-hash", OPT_RAW_HASH, NULL, 0, "Output the hash for the canonical "
    "representation of the object, in hexadecimal.", 0 },
  { "hash", OPT_HASH, "Algorithm", 0, "Hash algorithm (default sha1).", 0 },
  { "select", OPT_SELECT, "Operator", 0, "Select a subexpression "
    "(e.g \"caddr\") for processing.", 0 },
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
    (hash object hash_algorithm)
    (hash_name . int)
    (select object int_list)))
*/

static struct sexp_conv_options *
make_options(void)
{
  NEW(sexp_conv_options, self);
  self->input = SEXP_TRANSPORT;
  self->output = SEXP_ADVANCED;
  self->once = 0;
  self->mode = MODE_VANILLA;
  self->select = NULL;
  
  self->algorithms = make_alist(2,
				ATOM_MD5, &md5_algorithm,
				ATOM_SHA1, &sha1_algorithm,
				-1);
  self->hash = NULL;
  self->hash_name = ATOM_SHA1;
  
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
	CAST_SUBTYPE(hash_algorithm, h,
		     ALIST_GET(self->algorithms, self->hash_name));

	assert(h);

	self->hash = h;
	break;
      }
    case OPT_HASH:
      self->hash_name = lookup_hash(self->algorithms, arg, NULL, 0);
      
      if (!self->hash_name)
	argp_error(state, "Unknown hash algorithm '%s'.", arg);
      break;

    case OPT_SPKI_HASH:
      self->mode = MODE_SPKI_HASH;
      break;
    case OPT_RAW_HASH:
      self->mode = MODE_RAW_HASH;
      break;
    case OPT_SELECT:
      self->select = parse_select(arg);
      
      if (!self->select)
	argp_error(state, "Unsupported select operator '%s' (the supported "
		   "ones are ca[ad]*r).", arg);
      break;

    case OPT_ONCE:
      self->once = 1;
      break;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser,
  "Conversion: sexp-conv [options] <INPUT-SEXP >OUTPUT\n"
  "Fingerprinting: sexp-conv --raw-hash [ --hash=ALGORITHM ] <PUBLIC-KEY",
  "Reads an s-expression on stdin, and outputs the same "
  "s-expression on stdout, possibly using a different "
  "encoding. By default, output uses the advanced encoding. ",
  main_argp_children,
  NULL, NULL
};
  

#define SEXP_BUFFER_SIZE 1024
#define MAX_SEXP_SIZE 100000

int main(int argc, char **argv)
{
  struct sexp_conv_options *options = make_options();
  const struct exception *e;
  struct lsh_string *input;
  struct lsh_string *output;
  struct simple_buffer buffer;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  input = io_read_file_raw(STDIN_FILENO, 1000);
  if (!input)
    {
      werror("Failed to read stdin.\n");
      return EXIT_FAILURE;
    }

  simple_buffer_init(&buffer, input->length, input->data);

  while (!parse_eod(&buffer))
    {
      struct sexp *expr = sexp_parse(options->input, &buffer);

      if (!expr)
	{
	  werror("S-expression syntax error.\n");
	  return EXIT_FAILURE;
	}

      if (options->select)
	{
	  expr = process_select(options->select, expr);
	  if (!expr)
	    return EXIT_FAILURE;
	}

      /* FIXME: Perhaps move the addition of \n to sexp_format? */
      switch (options->mode)
	{
	case MODE_VANILLA:
	  output = sexp_format(expr, options->output, 0);

	  if (options->output != SEXP_CANONICAL)
	    output = ssh_format("%lfS\n", output);
	  break;
	  
	case MODE_SPKI_HASH:
	  output = sexp_format(spki_hash_sexp(options->hash,
					      options->hash_name,
					      expr),
			       options->output,
			       0);

	  if (options->output != SEXP_CANONICAL)
	    output = ssh_format("%lfS\n", output);
	  
	  break;
	case MODE_RAW_HASH:
	  output = ssh_format("%lxfS",
			      hash_string(options->hash,
					  sexp_format(expr, SEXP_CANONICAL, 0),
					  1));
	  break;

	default:
	  fatal("Internal error.\n");
	}

      e = write_raw(STDOUT_FILENO, output->length, output->data);
      if (e)
	{
	  werror("%z\n", e->msg);
	  return EXIT_FAILURE;
	}
      
      lsh_string_free(output);

      /* FIXME: Maybe gc here? */

      if (options->once)
	break;
    }

  lsh_string_free(input);
  
  gc_final();
  
  return EXIT_SUCCESS;
}
