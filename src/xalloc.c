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

#ifdef DEBUG_ALLOC

void *debug_malloc(size_t real_size)
{
  static int count = 4711;
  int *res;
  int size;
  
  /* Count size in ints, and round up */
  size = (real_size + sizeof(int)-1) / sizeof(int);
  
  res = malloc((size + 3)*sizeof(int));

  if (!res)
    return NULL;
  
  res[0] = count;
  res[1] = size;
  ((struct lsh_object *) (res + 2))->type = real_size;
  res[size+2] = ~count;
  count++;

  return (void *) (res + 2);
}

void debug_check_object(void *m, UINT32 expected_size)
{
  int real_size = ((struct lsh_object *) m)->type;
  if (real_size)
    { /* Heap allocated object */
      int *p = (int *) m;
      size_t size = p[-1];

      if (expected_size > real_size)
	fatal("Type error: pointing at too small an object!\n");	
      
      if (~p[-2] != p[size])
	fatal("Memory corrupted!\n");
      
      if (expected_size > size * sizeof(int))
	fatal("Memory corrupted!\n");
    }
}

void debug_free(void *m)
{
  int real_size = ((struct lsh_object *) m)->type;
  if (real_size)
    { /* Heap allocated object */
      int *p = (int *) m;
      size_t size = p[-1];
      
      if (~p[-2] != p[size])
	fatal("Memory corrupted!\n");

      p[-2] = p[size] = 0;
      
      free(p-2);
    }
  else
    fatal("Freeing an object not allcoated on the heap!\n");
}

#endif

void *xalloc(size_t size)
{
  void *res = lsh_malloc(size);
  if (!res)
    fatal("Virtual memory exhausted");
  return res;
}

struct lsh_string *lsh_string_alloc(UINT32 length)
{
  struct lsh_string *packet
    = xalloc(sizeof(struct lsh_string) - 1 + length);
  packet->length = length;
  packet->sequence_number = 0;
  return packet;
}

void lsh_string_free(struct lsh_string *packet)
{
  lsh_free(packet);
}
