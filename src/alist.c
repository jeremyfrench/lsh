/* alist.c
 *
 * Associations are implemented as linear tables.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
 

#include <assert.h>
#include <stdarg.h>

#include "alist.h"

#include "atoms.h"
#include "xalloc.h"

struct alist_table
{
  struct alist super;

  void *table[NUMBER_OF_ATOMS];
};

static void *do_get(struct alist *c, int atom)
{
  struct alist_table *closure = (struct alist_table *) c;

  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);
  
  MDEBUG(closure); 

  return closure->table[atom];
}

static void do_set(struct alist *c, int atom, void *value)
{
  struct alist_table *closure = (struct alist_table *) c;
  
  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);

  MDEBUG(closure);

  closure->table[atom] = value;
}

struct alist *make_alist(int n, ...)
{
  int i;
  va_list args;
  
  struct alist_table *res = xalloc(sizeof(struct alist_table));

  for (i = 0; i<NUMBER_OF_ATOMS; i++)
    res->table[i] = NULL;

  va_start(args, n);
  
  for (i=0; i<n; i++)
    {
      int atom = va_arg(args, int);
      void *value = va_arg(args, void *);

      res->table[atom] = value;
    }

  assert(va_arg(args, int) == -1);

  res->super.get = do_get;
  res->super.set = do_set;
  
  return &res->super;
}
