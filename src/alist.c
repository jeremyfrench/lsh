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
#include "werror.h"
#include "xalloc.h"

#define CLASS_DEFINE
#include "alist.h.x"
#undef CLASS_DEFINE

struct alist_node
{
  struct alist_node *next;
  int atom;
  struct lsh_object *value;
};

/* Prototypes */
#if 0
static void do_mark_table(struct lsh_object **table,
					void (*mark)(struct lsh_object *o));
#endif

static void *do_linear_get(struct alist *c, int atom);
static void do_linear_set(struct alist *c, int atom, void *value);

static void do_mark_list(struct alist_node *n,
				       void (*mark)(struct lsh_object *o));
static void do_free_list(struct alist_node *n);

static void *do_linked_get(struct alist *c, int atom);
static void do_linked_set(struct alist *c, int atom, void *value);

#include "alist.c.x"

/* NOTE: For a linear alist, all keys must be non-negative and less
 * than NUMBER_OF_ATOMS. */

/* CLASS:
   (class
     (name alist_linear)
     (super alist)
     (meta alist)
     (vars
       (table array (object lsh_object) NUMBER_OF_ATOMS))
     (methods do_linear_get do_linear_set))
*/

#if 0
struct alist_linear
{
  struct alist super;

  void *table[NUMBER_OF_ATOMS];
};
#endif

#if 0
void do_mark_table(struct lsh_object **table,
		   void (*mark)(struct lsh_object *o))
{
  unsigned i;

  for (i = 0; i<NUMBER_OF_ATOMS; i++)
    mark(table[i]);
}
#endif

static void *do_linear_get(struct alist *c, int atom)
{
  CAST(alist_linear, self, c);

  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);
  
  return self->table[atom];
}

static void do_linear_set(struct alist *c, int atom, void *value)
{
  CAST(alist_linear, self, c);
  
  assert(atom >= 0);
  assert(atom < NUMBER_OF_ATOMS);
  
  self->super.size += !self->table[atom] - !value; 
  
  self->table[atom] = value;
}

struct alist *make_linear_alist(int n, ...)
{
  int i;
  va_list args;
  
  NEW(alist_linear, res);

  res->super.size = 0;
  
  for (i = 0; i<NUMBER_OF_ATOMS; i++)
    res->table[i] = NULL;

  va_start(args, n);
  
  for (i=0; i<n; i++)
    {
      int atom = va_arg(args, int);
      struct lsh_object *value = va_arg(args, struct lsh_object *);

      if (!value)
	res->super.size++;

      res->table[atom] = value;
    }

  assert(va_arg(args, int) == -1);

  return &res->super;
}

/* NOTE: A linked alist does not have any limit on the size of its keys. */

/* CLASS:
   (class
     (name alist_linked)
     (super alist)
     (meta alist)
     (vars
       (head special "struct alist_node *"
             do_mark_list do_free_list))
     (methods do_linked_get do_linked_set))
*/

#if 0
struct alist_linked
{
  struct alist super;

  struct alist_node *head;
};
#endif

static void do_mark_list(struct alist_node *n,
			 void (*mark)(struct lsh_object *o))
{
  while(n)
    {
      mark(n->value);
      n = n->next;
    }
}

static void do_free_list(struct alist_node *n)
{
  while(n)
    {
      struct alist_node *old = n;
      n = n->next;
      lsh_space_free(old);
    }
}

static void *do_linked_get(struct alist *c, int atom)
{
  CAST(alist_linked, self, c);
  struct alist_node *p;
  
  assert(atom >= 0);
  
  for (p = self->head; p; p = p->next)
    if (p->atom == atom)
      return p->value;
  
  return NULL;
}

static void do_linked_set(struct alist *c, int atom, void *value)
{
  CAST(alist_linked, self, c);
  
  if (value)
    {
      struct alist_node *p;

      for (p = self->head; p; p = p->next)
	if (p->atom == atom)
	  {
	    p->value = value;
	    return;
	  }

      NEW_SPACE(p);
      p->next = self->head;
      p->atom = atom;
      p->value = value;

      self->head = p;

      self->super.size++;
    }
  else
    { /* Remove atom */
      struct alist_node **p;

      for(p = &self->head; *p; )
	{
	  struct alist_node *o = *p;
	  if (o->atom == atom)
	    {
	      *p = o->next;
	      lsh_space_free(o);

	      self->super.size--;
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
  
  struct alist *res;
  
  NEW(alist_linked, self);
  res = &self->super;

  res->size = 0;

  self->head = NULL;

  va_start(args, n);

  for (i=0; i<n; i++)
    {
      int atom = va_arg(args, int);
      struct lsh_object *value = va_arg(args, struct lsh_object *);

      if (atom < 0)
	fatal("Internal error!\n");
      do_linked_set(res, atom, value);
    }

  assert(va_arg(args, int) == -1);

#if 0
  res->get = do_linked_get;
  res->set = do_linked_set;
#endif
  
  return res;
}

