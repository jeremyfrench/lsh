/* lsh-export-key.c
 *
 * Reads an sexp in given form, and writes it in ssh2 form.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Jean-Pierre Stierlin, Niels Möller
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

/* Test output:
[nisse@cuckoo src]$ ./lsh-export-key < testkey.pub 
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "768-bit dsa"
AAAAB3NzaC1kc3MAAABhAJw3J7CMyAKiX8F1Mz1dNguVQi7VZQQrLl8DeWNQaSkqmIPjsc
zSn4Cjv9BOt8FM46AZbw+aSou0jpiFPJJiQjpT5U1ArPLoMqRpopqcZqcVubRKALTzytgw
vvXyoHb84wAAABUAmm14nnnHQtwx5ZUgRrjv98iv4KcAAABgENZmq1qm4jdJJB7IAC5Ecr
vcjhlACNcPD4UQ0Bgk66/MJOxvrwf0V+ZtTfb8ZaQlKdu84vB2VxVcB8zo0ds01I6eLG2f
/nDENvwp0TkNKf1uyEWPjNQGI/ImAqukiSWjAAAAYDe6o/C8faYCpuduLPQrl8Co6z7HgC
yIaRCzBjD8bY6L5qZp4G//8PVJVhxXh3vAS6LbgDCFoa2HZ1/vxHpML+gl3FPjAOxZPs27
B2CTISEmV3KYx5NJpyKC3IBw/ckP6Q==
---- END SSH2 PUBLIC KEY ----
*/

#if 0
#if macintosh
#include "lshprefix.h"
#include "lsh_context.h"
#endif
#endif

#include "algorithms.h"
#include "alist.h"
#include "atoms.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "lsh.h"
#include "lsh_argp.h"
#include "sexp_commands.h"
#include "spki.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "lsh-export-key.c.x"

static struct lsh_string *
make_header(const char *name, const char *value)
{
  return value
    ? ssh_format("%lz: %lz\n", name, value)
    : ssh_format("");
}

static struct lsh_string *
sexp_to_ssh2_key(struct sexp *expr,
                 struct export_key_options *options)
{
  struct sexp_iterator *i;
  struct verifier *v;
  
  if (!(i = sexp_check_type(expr, ATOM_PUBLIC_KEY)))
    {
      werror("Only conversion of public keys implemented.\n");
      return NULL;
    }

  expr = SEXP_GET(i);

  if (!expr)
    {
      werror("Invalid (empty) public key expression.\n");
      return NULL;
    }
      
  v = spki_make_verifier(options->algorithms, expr);
  if (!v)
    {
      werror("Unsupported algorithm\n");
      return NULL;
    }

  return ssh_format("---- BEGIN SSH2 PUBLIC KEY ----\n"
                    "%lfS"
                    "%lfS"
                    "\n%lfS\n"
                    "---- END SSH2 PUBLIC KEY ----\n",
                    make_header("Subject", options->subject),
                    make_header("Comment", options->comment),
                    encode_base64(PUBLIC_KEY(v), NULL, 1, 0, 1));
}

/* Option parsing */

const char *argp_program_version
= "lsh-export-key-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define OPT_INFILE 'r'
#define OPT_OUTFILE 'o'
#define OPT_SUBJECT 's'
#define OPT_COMMENT 'c'

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "input-file", OPT_INFILE, "Filename", 0, "Default is stdin", 0 },
  { "output-file", OPT_OUTFILE, "Filename", 0, "Default is stdout", 0 },
  { "subject", OPT_SUBJECT, "subject string", 0, "Add subject to output key.", 0 },
  { "comment", OPT_COMMENT, "comment string", 0, "Add comment to output key.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

/* GABA:
(class
  (name export_key_options)
  (vars
    (input . sexp_argp_state)
    (algorithms object alist)
    (infile . "const char *")
    (outfile . "const char *")
    (subject . "const char *")
    (comment . "const char *")))
*/

static struct export_key_options *
make_options(void)
{
  NEW(export_key_options, self);
  self->input = SEXP_TRANSPORT;
  self->infile = NULL;
  self->subject = NULL;
  self->comment = NULL;
  self->algorithms = all_signature_algorithms(NULL);

  return self;
}

static const struct argp_child
main_argp_children[] =
{
  { &sexp_input_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(export_key_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->input;
      // state->child_inputs[1] = &self->output;
      state->child_inputs[1] = NULL;
      break;
    case ARGP_KEY_END:
      break;
    case OPT_INFILE:
      self->infile = arg;
      break;
    case OPT_OUTFILE:
      self->outfile = arg;
      break;
    case OPT_SUBJECT:
      self->subject = arg;
      break;
    case OPT_COMMENT:
      self->comment = arg;
      break;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, NULL,
  "Reads an s-expression on stdin, and outputs the same "
  "s-expression on stdout, using OpenSSH/SSH2 encoding format.",
  main_argp_children,
  NULL, NULL
};
  

#define SEXP_BUFFER_SIZE 1024

#ifdef MACOS
char *applname = "lsh-export-key";
//char *defargstr = "-r identity.pub";
char *defargstr = "";
int appl_main(int argc, char **argv);
#define main appl_main
#endif

#define MAX_KEY_SIZE 10000

int main(int argc, char **argv)
{
  struct export_key_options *options = make_options();

  const struct exception *e;
  int in = STDIN_FILENO;
  int out = STDOUT_FILENO;
  
  struct lsh_string *input;
  struct sexp *expr;
  struct lsh_string *output;
    
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  if (options->infile)
    {
      in = open(options->infile, O_RDONLY);
      if (in < 0)
	{
	  werror("Failed to open '%z' for reading: %z\n",
		 options->infile, STRERROR(errno));
	  return EXIT_FAILURE;
	}
    }
  
  if (options->outfile)
    {
      out = open(options->outfile,
                 O_WRONLY | O_CREAT, 0666);
      if (out < 0)
        {
	  werror("Failed to open '%z' for writing: %z\n",
		 options->outfile, STRERROR(errno));
          return EXIT_FAILURE;
        }
    }

  /* Guess size 5000 */
  input = io_read_file_raw(in, 5000);
  
  if (!input)
    {
      werror("Failed to read '%z': %z\n",
             options->infile, STRERROR(errno));
      return EXIT_FAILURE;
    }

  expr = string_to_sexp(options->input, input, 1);
  if (!expr)
    {
      werror("Invalid S-expression\n");
      return EXIT_FAILURE;
    }

  output = sexp_to_ssh2_key(expr, options);
  if (!output)
    return EXIT_FAILURE;

  e = write_raw(out, output->length, output->data);

  if (e)
    {
      werror("%z\n", e->msg);
      return EXIT_FAILURE;
    }

  lsh_string_free(output);

  gc_final();
  
  return EXIT_SUCCESS;
}
  
