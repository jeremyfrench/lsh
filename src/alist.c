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

struct alist_linear
{
  struct alist super;

  void *table[NUMBER_OF_ATOMS];
};

static void *do_linear_get(struct alist *c, int atom)
{
  struct alist_linear *closure = (struct alist_linear *) c;

  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);
  
  MDEBUG(closure); 

  return closure->table[atom];
}

static void do_linear_set(struct alist *c, int atom, void *value)
{
  struct alist_linear *closure = (struct alist_linear *) c;
  
  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);

  MDEBUG(closure);
  
#if ALIST_USE_SIZE
  size += !closure->table[atom] - !value; 
#endif
  
  closure->table[atom] = value;
}

struct alist *make_linear_alist(int n, ...)
{
  int i;
  va_list args;
  
  struct alist_linear *res = xalloc(sizeof(struct alist_linear));

#if ALIST_USE_SIZE
  res->size = 0;
#endif
  
  for (i = 0; i<NUMBER_OF_ATOMS; i++)
    res->table[i] = NULL;

  va_start(args, n);
  
  for (i=0; i<n; i++)
    {
      int atom = va_arg(args, int);
      void *value = va_arg(args, void *);

#if ALIST_USE_SIZE
      if (!value)
	res->size ++;
#endif
      res->table[atom] = value;
    }

  assert(va_arg(args, int) == -1);

  res->super.get = do_linear_get;
  res->super.set = do_linear_set;
  
  return &res->super;
}

struct node
{
  struct node *next;
  int atom;
  void *value;
};
  
struct alist_linked
{
  struct alist super;

  struct node *head;
};

static void *do_linked_get(struct alist *c, int atom)
{
  struct alist_linked *closure = (struct alist_linked *) c;
  struct node *p;
  
  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);
  
  MDEBUG(closure); 

  for (p = self->first; p; p = p->next)
    if (p->atom == atom)
      return p->value;
  
  return NULL;
}

static void do_linked_set(struct alist *c, int atom, void *value)
{
  struct alist_linked *closure = (struct alist_linked *) c;
  
  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);

  MDEBUG(closure);

  if (value)
    {
      struct node *p;

      for (p = self->first; p; p = p->next)
	if (p->atom == atom)
	  {
	    p->value = value;
	    return;
	  }
      
      p = xalloc(sizeof(struct node));
      p->next = self->first;
      p->atom = atom;
      p->value = value;

      self->first = p;
#if ALIST_USE_SIZE
      self->size++;
#endif
    }
  else
    { /* Remove atom */
      struct node **p;

      for(p = &self->first; *p; )
	{
	  struct node *o = *p;
	  if (o->atom = atom)
	    {
	      *p = o->next;
	      lsh_free(o);

	      self->size--;
	      return;
	    }
	  p = &o->next;
	}
      /* Not found */
    }
}

struct alist *make_linked_alist(int n, ...)
{
  int i;
  va_list args;
  
  struct alist_linked *self = xalloc(sizeof(struct alist_linked));
  struct alist *res = &self->super;
  
#if ALIST_USE_SIZE
  self->size = 0;
#endif

  self->first = NULL;

  va_start(args, n);

  for (i=0, p = NULL; i<n; i++)
    {
      int atom = va_arg(args, int);
      void *value = va_arg(args, void *);

      do_linked_set(res, atom, value);
    }

  assert(va_arg(args, int) == -1);

  res->get = do_linked_get;
  res->set = do_linked_set;
  
  return res;
}


  
