/* lsh-make-seed.c
 *
 * Creates an initial yarrow seed file
 *
 * $id:$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001 Niels Möller
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
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/yarrow.h"

#include <stdlib.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "lsh-make-seed.c.x"

/* Option parsing */

const char *argp_program_version
= "lsh-make-seed-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

/* GABA:
   (class
     (name lsh_make_seed_options)
     (vars
       (filename string)
       (force . int)))
*/

static struct lsh_make_seed_options *
make_options(void)
{
  NEW(lsh_make_seed_options, self);

  self->filename = NULL;
  self->force = 0;
  
  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "output-file", 'o', "Filename", 0, "Default is ~/.lsh/seed-file", 0 },
  { "force", 'f', NULL, 0, "Overwrite any existing seed file.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};
  
static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_make_seed_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;

    case ARGP_KEY_END:
      if (!self->filename)
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
	      self->filename = ssh_format("%lz/.lsh/identity", home);
	    }
	}
      break;
      
    case 'o':
      self->filename = make_string(arg);
      break;

    case 'f':
      self->force = 1;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  NULL,
  "Creates an initial random seed file for the YARROW pseudorandomness"
  "generator used by lsh.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{
  struct lsh_make_seed_options_options *options = make_options();
  int fd;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  return EXIT_SUCCESS;
}
