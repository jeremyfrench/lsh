/* lsh-writekey.c
 *
 * Reads a (private) key on stdin, and saves it a private and a public file.
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

#include "algorithms.h"
#include "crypto.h"
#include "dsa.h"
#include "format.h"
#include "io_commands.h"
#include "interact.h"
#include "publickey_crypto.h"
#include "sexp.h"
#include "spki.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "lsh-writekey.c.x"

/* Option parsing */

const char *argp_program_version
= "lsh-writekey-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

/* GABA:
   (class
     (name lsh_writekey_options)
     (vars
       ; Base filename
       (file string)

       (tty object interact)
       
       (label string)
       (style . sexp_argp_state)
       (passphrase string)

       (crypto_algorithms object alist)
       (signature_algorithms object alist)
       (r object randomness)
       
       (crypto_name . int)
       (crypto object crypto_algorithm)
       (iterations . UINT32)))
*/

static struct lsh_writekey_options *
make_lsh_writekey_options(void)
{
  NEW(lsh_writekey_options, self);
  self->file = NULL;

  /* We don't need window change tracking. */
  self->tty = make_unix_interact();
    
  self->label = NULL;
  self->style = -1;

  self->passphrase = NULL;
  self->iterations = 1500;

  self->crypto_algorithms = all_symmetric_algorithms();

  /* NOTE: We don't need any randomness here, as we won't be signing
   * anything. */
  self->signature_algorithms = all_signature_algorithms(NULL);

  /* We use this only for salt and iv generation. */
  self->r = make_user_random(getenv("HOME"));
  
  /* A better default would be crypto_cbc(make_des3()) */
  self->crypto = NULL;
  
  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "output-file", 'o', "Filename", 0, "Default is ~/.lsh/identity", 0 },
  { "iteration-count", 'i', "PKCS#5 iteration count", 0, "Default is 1500", 0 },
  { "crypto", 'c', "Algorithm", 0, "Encryption algorithm for the private key file.", 0 },
  { "label", 'l', "Text", 0, "Unencrypted label for the key.", 0 },
  { "passphrase", 'p', "Password", 0, NULL, 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
main_argp_children[] =
{
  { &sexp_output_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};


static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_writekey_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->style;
      state->child_inputs[1] = NULL;
      break;

    case ARGP_KEY_END:
      if (!self->file)
	{
	  char *home = getenv("HOME");
	  struct lsh_string *s;
	  
	  if (!home)
	    {
	      argp_failure(state, EXIT_FAILURE, 0, "$HOME not set.");
	      return EINVAL;
	    }
	  else
	    {
	      s = ssh_format("%lz/.lsh", home);
	      if (mkdir(lsh_get_cstring(s), 0755) < 0)
		{
		  if (errno != EEXIST)
		    argp_failure(state, EXIT_FAILURE, errno, "Creating directory %s failed.", s->data);
		}
	      lsh_string_free(s);
	      self->file = ssh_format("%lz/.lsh/identity", home);
	    }
	}
      if (self->crypto)
	{
	  if (!self->label)
	    {
	      const char *name = getenv("LOGNAME");
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 300
#endif
	      char host[MAXHOSTNAMELEN];
	  
	      if (!name)
		{
		  argp_failure(state, EXIT_FAILURE, 0,
			       "LOGNAME not set. Please use the -l option.");
		  return EINVAL;
		}

	      if ( (gethostname(host, sizeof(host)) < 0)
		   && (errno != ENAMETOOLONG) )
		argp_failure(state, EXIT_FAILURE, errno,
			     "Can't get the host name. Please use the -l option.");
	      
	      self->label = ssh_format("%lz@%lz", name, host);
	    }
	  while (!self->passphrase)
	    {
	      struct lsh_string *pw;
	      struct lsh_string *again;

	      pw = INTERACT_READ_PASSWORD(self->tty, 500,
					  ssh_format("Enter new passphrase: "), 1);
	      if (!pw)
		argp_failure(state, EXIT_FAILURE, 0, "Aborted.");

	      again = INTERACT_READ_PASSWORD(self->tty, 500,
					     ssh_format("Again: "), 1);
	      if (!again)
		argp_failure(state, EXIT_FAILURE, 0, "Aborted.");

	      if (lsh_string_eq(pw, again))
		self->passphrase = pw;
	      else
		lsh_string_free(pw);
		  
	      lsh_string_free(again);
	    }
	}
      break;
      
    case 'o':
      self->file = make_string(arg);
      break;

    case 'i':
      {
	long i;
	char *end;
	i = strtol(arg, &end, 0);

	if ((end == arg) || *end || (i < 1))
	  {
	    argp_failure(state, EXIT_FAILURE, 0, "Invalid iteration count.");
	    return EINVAL;
	  }
	else if (i > PKCS5_MAX_ITERATIONS)
	  {
	    argp_error(state, "Iteration count ridiculously large (> %d).",
		       PKCS5_MAX_ITERATIONS);
	    return EINVAL;
	  }
	else
	  self->iterations = i;

	break;
      }

    case 'c':
      {
	int name = lookup_crypto(self->crypto_algorithms, arg, &self->crypto);

	if (name)
	  self->crypto_name = name;
	else
	  {
	    list_crypto_algorithms(state, self->crypto_algorithms);
	    argp_error(state, "Unknown crypto algorithm '%s'.", arg);
	  }
	break;
      }
      
    case 'l':
      self->label = ssh_format("%lz", arg);
      break;
      
    case 'p':
      self->passphrase = ssh_format("%lz", arg);
      break;
    }
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  NULL,
  ( "Splits a keypair in one private and one public file, "
    "optionally encrypting the private file using a passphrase.\v"
    "Common usage is to pipe the output from lsh-keygen into this program."
    ),
  main_argp_children,
  NULL, NULL
};

static int
open_private_file(const struct lsh_string *file)
{
  int fd = open(lsh_get_cstring(file),
                O_CREAT | O_EXCL | O_WRONLY,
                0600);

  if (fd < 0)
    werror("Failed to open `%S'for writing: %z\n"
           "lsh-writekey doesn't overwrite existing key files.\n"
           "If you *really* want to do that, you should delete\n"
           "the existing files first\n",
           file, STRERROR(errno));

  return fd;
}

static int
open_public_file(const struct lsh_string *file)
{
  struct lsh_string *s = ssh_format("%lS.pub", file);
  
  int fd = open(lsh_get_cstring(s),
                O_CREAT | O_EXCL | O_WRONLY,
                0644);

  if (fd < 0)
    werror("Failed to open `%z'for writing: %z\n"
           "lsh-writekey doesn't overwrite existing key files.\n"
           "If you *really* want to do that, you should delete\n"
           "the existing files first\n",
           file, STRERROR(errno));

  lsh_string_free(s);
  
  return fd;
}

static struct lsh_string *
process_private(struct sexp *key,
                struct lsh_writekey_options *options)
{
  struct sexp *expr = key;

  if (options->crypto)
    {
      CAST_SUBTYPE(mac_algorithm, hmac,
                   ALIST_GET(options->crypto_algorithms, ATOM_HMAC_SHA1));
      assert(hmac);
      
      expr = spki_pkcs5_encrypt(options->r,
                                options->label,
                                ATOM_HMAC_SHA1,
                                hmac,
                                options->crypto_name,
                                options->crypto,
                                10, /* Salt length */
                                options->passphrase,
                                options->iterations,
                                sexp_format(key, SEXP_CANONICAL, 0));
    }
  return sexp_format(expr,
                     (options->style > 0) ? options->style : SEXP_CANONICAL,
                     0);
}

static struct lsh_string *
process_public(struct sexp *key,
               struct lsh_writekey_options *options)
{
  struct signer *s;
  struct verifier *v;
  
  s = spki_sexp_to_signer(options->signature_algorithms,
                          key, NULL);
  
  if (!s)
    return NULL;

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  return sexp_format(spki_make_public_key(v),
                     (options->style > 0) ? options->style : SEXP_TRANSPORT,
                     0);
}

int
main(int argc, char **argv)
{
  struct lsh_writekey_options *options = make_lsh_writekey_options();
  int private_fd;
  int public_fd;
  struct lsh_string *input;
  struct lsh_string *output;
  struct sexp *key;
  const struct exception *e;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  private_fd = open_private_file(options->file);
  if (private_fd < 0)
    return EXIT_FAILURE;

  public_fd = open_public_file(options->file);
  if (public_fd < 0)
    return EXIT_FAILURE;

  input = io_read_file_raw(STDIN_FILENO, 2000);

  if (!input)
    {
      werror("Failed to read key from stdin: %z\n",
             STRERROR(errno));
      return EXIT_FAILURE;
    }

  key = string_to_sexp(SEXP_TRANSPORT, input, 1);

  if (!key)
    {
      werror("S-expression syntax error.\n");
      return EXIT_FAILURE;
    }

  output = process_private(key, options);
  if (!output)
    return EXIT_FAILURE;

  e = write_raw(private_fd, output->length, output->data);
  lsh_string_free(output);

  if (e)
    {
      werror("Writing private key failed: %z\n",
             e->msg);
      return EXIT_FAILURE;
    }

  output = process_public(key, options);
  if (!output)
    return EXIT_FAILURE;

  e = write_raw(public_fd, output->length, output->data);
  lsh_string_free(output);
  
  if (e)
    {
      werror("Writing public key failed: %z\n",
             e->msg);
      return EXIT_FAILURE;
    }
  
  gc_final();
  
  return EXIT_SUCCESS;
}
