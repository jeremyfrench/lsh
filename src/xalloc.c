/* xalloc.c
 *
 *
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

#include "xalloc.h"
#include "werror.h"

#include <stdlib.h>

#ifdef DEBUG_ALLOC

#define lsh_free debug_free
#define lsh_malloc debug_malloc

/* There are two sets of allocation functions: Low level allocation *
 * that can allocate memory for any purpose, and object allocators
 * that assume that the allocated object begins with a type field. */

/* NOTE: This doesn't work if there are types that require other
 * alignment than int boundaries. But it doesn't matter much if the
 * optional debug code isn't fully portable. */

#define SIZE_IN_INTS(x) (((x) + sizeof(int)-1) / sizeof(int))

static void *debug_malloc(size_t real_size)
{
  static int count = 4711;
  int *res;
  int size = SIZE_IN_INTS(real_size);
  
  res = malloc((size + 3)*sizeof(int));

  if (!res)
    return NULL;
  
  res[0] = count;
  res[1] = real_size;
  /* ((struct lsh_object *) (res + 2))->type = real_size; */
  res[size+2] = ~count;
  count++;

  return (void *) (res + 2);
}

static void debug_free(void *m)
{
  if (m)
    {
      int *p = (int *) m;
      int real_size = p[-1];
      int size = SIZE_IN_INTS(real_size);
      
      if (~p[-2] != p[size])
	fatal("Memory corrupted!\n");
      
      p[-2] = p[size] = 0;
      
      free(p-2);
    }
}

#else  /* !DEBUG_ALLOC */

#define lsh_free free
#define lsh_malloc malloc

#endif /* !DEBUG_ALLOC */

static void *xalloc(size_t size)
{
  void *res = lsh_malloc(size);
  if (!res)
    fatal("Virtual memory exhausted");
  return res;
}

struct lsh_string *lsh_string_alloc(UINT32 length)
{
  struct lsh_string *s
    = xalloc(sizeof(struct lsh_string) - 1 + length);
#ifdef DEBUG_ALLOC
  s->header.magic = -1717;
#endif
  s->length = length;
  s->sequence_number = 0;
  return s;
}

void lsh_string_free(struct lsh_string *s)
{
#ifdef DEBUG_ALLOC
  if (s->header.magic != -1717)
    fatal("lsh_string_free: Not string!\n");
#endif
  lsh_free(s);
}

struct lsh_object *lsh_object_alloc(struct lsh_class *class)
{
  struct lsh_object *instance = xalloc(class->size);
  instance->isa = class;
  instance->alloc_method = LSH_ALLOC_HEAP;

  gc_register(instance);

  return instance;
}

/* Should be called *only* by the gc */
void lsh_object_free(struct lsh_object *o)
{
  if (o->alloc_method != LSH_ALLOC_HEAP)
    fatal("lsh_object_free: Object not allocated on the heap!\n");

  if (o->isa->free_instance)
    o->isa->free_instance(o);
  
  lsh_free(o);
};

#if 0
void *lsh_object_alloc(size_t size)
{
  struct lsh_object *self = xalloc(size);
#ifdef DEBUG_ALLOC
  self->size = size;
#endif
  self->alloc_method = LSH_ALLOC_HEAP;
  self->marked = 0;
  return (void *) self;
};

void lsh_object_free(void *p)
{
  if ( ((struct lsh_object *) p)->alloc_method != LSH_ALLOC_HEAP)
    fatal("lsh_object_free: Object not allocated on the heap!\n");
  lsh_free(p);
};
#endif

#ifdef DEBUG_ALLOC
struct lsh_object *lsh_object_check(struct lsh_class *class,
				    struct lsh_object *instance)
{
  if (instance->marked)
    fatal("lsh_object_check: Unexpected marked object!\n");

  if (instance->dead)
    fatal("lsh_object_check: Reference to dead object!\n");

  if (instance->isa != class)
    fatal("lsh_object_check: Type error!\n");

  return instance;
}

struct lsh_object *lsh_object_check_subtype(struct lsh_class *class,
					    struct lsh_object *instance)
{
  struct lsh_class *type;
  
  if (instance->marked)
    fatal("lsh_object_check: Unexpected marked object!\n");

  if (instance->dead)
    fatal("lsh_object_check: Reference to dead object!\n");

  for (type = instance->isa; type; type=type->super_class)
    if (type == class)
      return instance;

  fatal("lsh_object_check_subtype: Unexpected marked object!\n");
}
#endif /* DEBUG_ALLOC */

#ifdef DEBUG_ALLOC
void *lsh_space_alloc(size_t size)
{
  int * p = xalloc(size + sizeof(int));

  *p = -1919;

  return (void *) (p + 1);
}

void lsh_space_free(void *p)
{
  int *m = ((int *) p) - 1;

  if (*m != -1919)
    fatal("lsh_free_space: Type error!\n");

  lsh_free(m);
}

#else /* !DEBUG_ALLOC */

void *lsh_space_alloc(size_t size)
{
  return xalloc(size);
}

void lsh_space_free(void *p)
{
  lsh_free(p);
}

#endif /* !DEBUG_ALLOC */
