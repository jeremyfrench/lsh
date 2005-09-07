/* arglist.h
 *
 * Convenience functions for building argument lists for exec. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "arglist.h"

#include "werror.h"

#define DEFAULT_SIZE 10

void
arglist_init(struct arglist *args)
{
  args->size = DEFAULT_SIZE;
  args->argc = 0;
  args->argv = malloc(args->size * sizeof(args->argv[0]));

  if (!args->argv)
    fatal("Memory exhausted.\n");
}

void
arglist_clear(struct arglist *args)
{
  free(args->argv);
  args->argv = NULL;
}

void
arglist_push(struct arglist *args, const char *s)
{
  assert(args->argc < args->size);
  if (args->argc + 1 == args->size)
    {
      unsigned n = 2 * args->size;
      void *p = realloc(args->argv, n * sizeof(args->argv[0]));
      if (!p)
	fatal("Memory exhausted.\n");
      args->size = n;
      args->argv = p;
    }
  args->argv[args->argc++] = s;
  args->argv[args->argc] = NULL;
}

/* Pushes the catenation of option and argument (this memory is
   leaked). Needed for options with an optinal argument. */
void
arglist_push_optarg(struct arglist *args,
		    const char *opt, const char *arg)
{
  char *s;

  if (asprintf(&s, "%s%s", opt, arg) < 0)
    fatal("Virtual memory exhausted.\n");
  arglist_push(args, s);  
}
