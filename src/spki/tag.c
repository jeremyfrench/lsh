/* tag.c
 *
 * Operations on SPKI "tags", i.e. authorization descriptions. */

/* libspki
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "tag.h"

#include "nettle/buffer.h"
#include "nettle/sexp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

enum spki_tag_type
  {
    SPKI_TAG_ERROR = 0,
    SPKI_TAG_ATOM,
    SPKI_TAG_LIST,
    SPKI_TAG_ANY,
    SPKI_TAG_SET,
    SPKI_TAG_PREFIX,
    SPKI_TAG_RANGE
  };

static int
display_equal(struct sexp_iterator *a, struct sexp_iterator *b)
{
  assert(a->type == SEXP_ATOM);
  assert(b->type == SEXP_ATOM);

  if (!a->display && !b->display)
    return 1;
  if (!a->display || !b->display)
    return 0;

  return (a->display_length == b->display_length
	  && !memcmp(a->display, b->display, a->display_length));
}

static int
atom_equal(struct sexp_iterator *a, struct sexp_iterator *b)
{
  assert(a->type == SEXP_ATOM);
  assert(b->type == SEXP_ATOM);

  return (a->atom_length == b->atom_length
	  && display_equal(a,b)
	  && !memcmp(a->atom, b->atom, a->atom_length));
}

static enum spki_tag_type
spki_tag_classify(struct sexp_iterator *i)
{
  switch(i->type)
    {
    default:
      abort();
      
    case SEXP_END:
      return 0;
      
    case SEXP_ATOM:
      return SPKI_TAG_ATOM;
      
    case SEXP_LIST:
      if (!sexp_iterator_enter_list(i))
	return 0;

      if (i->type == SEXP_ATOM && !i->display
	  && i->atom_length == 1 && i->atom[0] == '*')
	{
	  enum spki_tag_type type;
	  
	  if (!sexp_iterator_next(i))
	    return 0;

	  if (i->type == SEXP_END)
	    return sexp_iterator_exit_list(i) ? SPKI_TAG_ANY : 0;

	  if (i->type != SEXP_ATOM || i->display)
	    return 0;

#define CASE(x, t)				\
case sizeof("" x) - 1:				\
  if (!memcmp(i->atom, x, sizeof("" x) - 1)) 	\
    { type = t; break; }			\
  return 0

	  switch (i->atom_length)
	    {
	    default:
	      return 0;
	      
	    CASE("set", SPKI_TAG_SET);
	    CASE("range", SPKI_TAG_RANGE);
	    CASE("prefix", SPKI_TAG_PREFIX);
	    }

	  return sexp_iterator_next(i) ? type : 0;
	}
      else
	return SPKI_TAG_LIST;
    }
}

static int
set_includes(struct sexp_iterator *delegated,
	     struct sexp_iterator *request)
{
  /* The request is included if it's including in any of
   * the delegations in the set. */
  while (delegated->type != SEXP_END)
    {
      struct sexp_iterator work = *request;
      if (spki_tag_includes(delegated, &work))
	{
	  if (!sexp_iterator_exit_list(delegated))
	    abort();
	  *request = work;
	  return 1;
	}
      if (!sexp_iterator_next(delegated))
	abort();
    }
  return 0;
}

static int
list_includes(struct sexp_iterator *delegated,
	      struct sexp_iterator *request)
{
  /* There may be fewer elements in the request list than in the
   * delegation list. A delegation list implicitly includes any number
   * of (*) forms at the end needed to match all elements in the
   * request form. */

  while (request->type != SEXP_END)
    {
      if (delegated->type == SEXP_END)
	break;

      if (!spki_tag_includes(delegated, request))
	return 0;
    }
  
  if (delegated->type != SEXP_END)
    return 0;

  /* Success */
  if (!sexp_iterator_exit_list(delegated))
    abort();

  return sexp_iterator_exit_list(request);
}

/* Returns true if the requested authorization is included in the
 * delegated one. For now, star forms are recognized only in the
 * delegation, not in the request.
 *
 * Compares only the first element on each list, and, on success,
 * advances the corresponding iterator past it. */
int
spki_tag_includes(struct sexp_iterator *delegated,
		  struct sexp_iterator *request)
{
  switch (spki_tag_classify(delegated))
    {
    default:
      return 0;

    case SPKI_TAG_ATOM:
      if (request->type == SEXP_ATOM
	  && atom_equal(delegated, request))
	{
	  if (!sexp_iterator_next(delegated))
	    abort();
	  return sexp_iterator_next(request);
	}
      return 0;

    case SPKI_TAG_LIST:
      return sexp_iterator_enter_list(request)
	&& list_includes(delegated, request);
      
    case SPKI_TAG_ANY:
      return 1;

    case SPKI_TAG_SET:
      return set_includes(delegated, request);

      /* Other star forms not yet implemented. */
    }
}


#if 0
/* Intersecting tags. */

/* FIXME: Collaps redundant set expressions, like
 *
 * (* set foo)                     --> foo
 * (* set (* set a b) (* set c d)) --> (* set a b c d)
 *
 * This may require conversion fo the tags into a tree data
 * structure. */

/* Called when the intersection equals a, so copy it. */
static int
copy_intersect(struct nettle_buffer *buffer,
	       struct sexp_iterator *a)
{
  unsigned length;
  const uint8_t *data;

  return (data = sexp_iterator_subexpr(a, &length))
    && nettle_buffer_write(buffer, length, data);
}

static int
set_intersect(struct nettle_buffer *buffer,
	      struct sexp_iterator *s,
	      struct sexp_iterator *a)
{
  /* Needed in case we need to back up after failure. */
  unsigned start = buffer->size;
  unsigned first;
  unsigned n;
  struct sexp_iterator a_start = *a;
  struct sexp_iterator a_end;
	  
  /* Create a new set by intersecting each element with a. */
  if (!nettle_buffer_write(buffer, "(1:*3:set"))
    return 0;
  
  first = buffer->size;
  
  for (n = 0; l->type != SEXP_END; )
    {
      struct sexp_iterator work = *a;
      if (spki_tag_intersect(buffer, l, &work))
	{
	  if (!n)
	    a_end = work;
	  n++;
	}
      if (!sexp_iterator_next(l))
	goto fail;
    }
  
  if (n && NETTLE_BUFFER_PUTC(buffer, ')'))
    {
      *a = a_end;
      return 1;
    }

 fail:
  buffer->size = start;
  return 0;
}

static int
list_intersect(struct nettle_buffer *buffer,
	       struct sexp_iterator *l,
	       struct sexp_iterator *a)
{
  if (!sexp_iterator_enter_list(l))
    abort();

  if (MAGIC(l, "*"))
    {
      if (l->type == SEXP_END)
	return sexp_iterator_exit_list(l)
	  && copy_intersect(buffer, a);

      if (MAGIC(l, "set"))
	return set_intersect(l, a, 0);

      else
	/* Not yet implemented */
	return 0;
    }

  /* The other expression must be a list. */
  if (!sexp_iterator_enter_list(a))
    return 0;

  if (MAGIC(a, '*'))
    return magic_intersect(
  
}

/* Tries to intersect the current expressions on the A and B lists. If
 * intersection is nonempty, it is written to BUFFER, and the function
 * returns 1. Otherwise, writes nothing to BUFFER, and returns 0. */
int
spki_tag_intersect(struct nettle_buffer *buffer,
		   struct sexp_iterator *a,
		   struct sexp_iterator *b)
{
  assert(a->type != SEXP_END);
  assert(a->type != SEXP_END);
  
  if (a->type == SEXP_LIST)
    return list_intersect(buffer, in_set, a, b);
  if (b->type == SEXP_LIST)
    return list_intersect(buffer, in_set, b, a);

  return atom_equal(a, b)
    && sexp_iterator_next(b)
    && copy_intersect(buffer, a);
}
#endif
