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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "server.h"

#include "atoms.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "sexp.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "server.h.x"
#undef GABA_DEFINE

/* Handles lists of services or subsystems. MODULES is a list { name,
   program, name, program, ..., NULL }. */ 
const char *
server_lookup_module(const char **modules,
		     uint32_t length, const uint8_t *name)
{
  unsigned i;
  if (memchr(name, 0, length))
    return NULL;

  for (i = 0; modules[i]; i+=2)
    {
      assert(modules[i+1]);
      if ((length == strlen(modules[i]))
	  && !memcmp(name, modules[i], length))
	return modules[i+1];
    }
  return NULL;
}

/* The config file is located, in order of decreasing precendence:
 *
 *   1. The --config-file command line option.
 *
 *   2. The <PROGRAM>_CONF environment variable.
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
  OPT_SERVICE
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

struct service_config *
make_service_config(void)
{
  NEW(service_config, self);
  self->name = NULL;
  arglist_init (&self->args);

  return self;
}

static const struct argp_option
service_options[] =
{
  { "service", OPT_SERVICE, "NAME { COMMAND LINE }", 0,
    "Service to offer.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t
service_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST_SUBTYPE(service_config, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;

    case OPT_SERVICE:
      if (self->name)
	argp_error (state, "Multiple --service options not supported.");

      self->name = arg;
      if (state->next >= state->argc
	  || strcmp (state->argv[state->next], "{"))
	argp_error (state,
		      "--service requires a name and a brace-delimited command line.");
      else
	{
	  unsigned level = 1;
	  
	  for (state->next++; state->next < state->argc; )
	    {
	      const char *s = state->argv[state->next++];
	      if (!strcmp(s, "{"))
		level++;
	      else if (!strcmp(s, "}"))
		{
		  level--;
		  if (!level)
		    {
		      if (!self->args.argc)
			argp_error (state, "Empty command line for --service.");

		      return 0;
		    }
		}
	      arglist_push (&self->args, s);
	    }
	  argp_error (state, "Unexpected end of arguments while parsing --service command line.");
	}
      break;
    }
  return 0;
}

const struct argp
service_argp =
{
  service_options,
  service_argp_parser,
  NULL, NULL,
  NULL,
  NULL, NULL
};
