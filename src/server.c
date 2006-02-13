/* server.c
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include "server.h"

#include "atoms.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "sexp.h"
#include "spki.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "server.h.x"
#undef GABA_DEFINE

/* Read server's private key */

static void
add_key(struct alist *keys,
        struct keypair *key)
{
  if (ALIST_GET(keys, key->type))
    werror("Multiple host keys for algorithm %a\n", key->type);
  ALIST_SET(keys, key->type, &key->super);
}

int
read_host_key(const char *file,
              struct alist *signature_algorithms,
              struct alist *keys)
{
  int fd = open(file, O_RDONLY);
  struct lsh_string *contents;
  struct signer *s;
  struct verifier *v;
  
  int algorithm_name;

  if (fd < 0)
    {
      werror("Failed to open `%z' for reading %e\n", file, errno);
      return 0;
    }
  
  contents = io_read_file_raw(fd, 5000);
  if (!contents)
    {
      werror("Failed to read host key file `%z': %e\n", file, errno);
      close(fd);
      return 0;
    }
  close(fd);

  s = spki_make_signer(signature_algorithms,
		       contents,
		       &algorithm_name);
  lsh_string_free(contents);
  
  if (!s)
    {
      werror("Invalid host key\n");
      return 0;
    }

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  switch (algorithm_name)
    {
    case ATOM_DSA:
      add_key(keys,
              make_keypair(ATOM_SSH_DSS, PUBLIC_KEY(v), s));
      break;

    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      add_key(keys,
              make_keypair(ATOM_SSH_RSA, PUBLIC_KEY(v), s));
      break;

    default:
      werror("read_host_key: Unexpected algorithm %a.\n", algorithm_name);
    }
  return 1;
}


/* The config file is located, in order of decreasing precendence:
 *
 *   1. The --config-file command line option.
 *
 *   2. The <PROGRAM>_CONFIG_FILE environment variable.
 *
 *   3. The LSHD_CONFIG_DIR environment variable, combined with the
 *      default file name.
 *
 *   4. The default directory, and the default file name, e.g.,
 *       /etc/lshd/lshd_config.
 */ 
static int
server_parse_config_file(const char *file,
			 const char *default_file,			
			 const char *env_file,
			 const struct config_parser *parser,
			 void *input)
{
  struct lsh_string *s = NULL;
  struct lsh_string *contents;
  int res;

  int fd;

  if (!file)
    file = getenv(env_file);

  if (!file)
    {
      const char *dir;

      GET_FILE_ENV(dir, LSHD_CONFIG_DIR);
      s = ssh_format("%lz/%lz", dir, default_file);
      file = lsh_get_cstring(s);
    }

  fd = open(file, O_RDONLY);
  if (fd < 0)
    {
      werror("Opening config file `%z' failed: %e.\n",
	     file, errno);
      lsh_string_free(s);
      return errno;
    }

  contents = io_read_file_raw(fd, 10000);
  close(fd);
  if (!contents)
    {
      werror("Reading config file `%z' failed: %e.\n",
	     file, errno);

      lsh_string_free(s);
      return errno;
    }

  res = server_config_parse_string(parser, lsh_get_cstring(s),
				   STRING_LD(contents),
				   input);
  lsh_string_free(s);
  lsh_string_free(contents);  

  return res;
}

void
init_server_config(struct server_config *self,
		   const struct config_parser *parser,
		   const char *default_file,			
		   const char *env_variable)
{
  init_werror_config(&self->super);

  self->parser = parser;
  self->default_file = default_file;
  self->env_variable = env_variable;

  self->config_file = NULL;
  self->use_example = 0;
}

struct server_config *
make_server_config(const struct config_parser *parser,
		   const char *default_file,			
		   const char *env_variable)
{
  NEW(server_config, self);
  init_server_config(self, parser, default_file, env_variable);
  return self;
}

enum {  
  OPT_CONFIG_FILE = 0x200,
  OPT_PRINT_EXAMPLE,
  OPT_USE_EXAMPLE,
};

static const struct argp_option
server_options[] =
{
  { NULL, 0, NULL, 0, "Config file use:", 0 },
  { "config-file", OPT_CONFIG_FILE, "FILE", 0,
    "Location of configuration file.", 0 },
  { "print-example-config", OPT_PRINT_EXAMPLE, NULL, 0,
    "Print an example configuration file.", 0 },
  { "use-example-config", OPT_USE_EXAMPLE, NULL, 0,
    "Don't read any config file; use the example configuration." ,0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
server_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
server_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST_SUBTYPE(server_config, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      break;

    case ARGP_KEY_END:
      if (self->config_file && self->use_example)
	argp_error(state, "The options --config-file "
		   "and --use-example-config are mutually exclusive.");

      if (self->use_example)
	{
	  int err = server_config_parse_example(self->parser, self);
	  if (err)
	    argp_failure(state, EXIT_FAILURE, err,
			 "Processing of the example configuration failed");
	}
      else
	{
	  int err = server_parse_config_file(self->config_file,
					     self->default_file,
					     self->env_variable,
					     self->parser,
					     self);
	  if (err)
	    argp_failure(state, EXIT_FAILURE, err,
			 "Processing of the configuration file failed.");
	}
      if (!werror_init(&self->super))
	argp_failure(state, EXIT_FAILURE, errno, "Failed to open log file");

      break;

    case OPT_CONFIG_FILE:
      self->config_file = arg;
      break;

    case OPT_PRINT_EXAMPLE:
      server_config_print_example(self->parser, stdout);
      exit(EXIT_SUCCESS);

    case OPT_USE_EXAMPLE:
      self->use_example = 1;
      break;
    }
  return 0;
}

const struct argp
server_argp =
{
  server_options,
  server_argp_parser,
  NULL, NULL,
  server_argp_children,
  NULL, NULL
};
