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

#ifndef LSH_ARGLIST_H_INCLUDED
#define LSH_ARGLIST_H_INCLUDED

struct arglist
{
  unsigned size;
  unsigned argc;
  const char **argv;
};

void
arglist_init(struct arglist *args);

void
arglist_clear(struct arglist *args);

void
arglist_push(struct arglist *args, const char *s);

void
arglist_push_optarg(struct arglist *args,
		    const char *opt, const char *arg);


#endif /* LSH_ARGLIST_H_INCLUDED */
