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

#include "nettle/sexp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

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

static int
tag_magic(struct sexp_iterator *i,
	  unsigned length, const uint8_t *magic)
{
  return i->type == SEXP_ATOM
    && !i->display
    && i->atom_length == length
    && !memcmp(i->atom, magic, length);
}

#define MAGIC(i, m) tag_magic(i, sizeof("" m) - 1, m)

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
  switch (delegated->type)
    {
    case SEXP_ATOM:
      if (request->type == SEXP_ATOM
	  && atom_equal(delegated, request))
	{
	  if (!sexp_iterator_next(delegated))
	    abort();
	  return sexp_iterator_next(request);
	}
      return 0;
      
    case SEXP_END:
      abort();
      
    case SEXP_LIST:
      if (!sexp_iterator_enter_list(delegated))
	abort();

      if (MAGIC(delegated, "*"))
	{
	  if (!sexp_iterator_next(delegated))
	    abort();

	  /* The form (*) matches anything */
	  if (delegated->type == SEXP_END)
	    {
	      if (!sexp_iterator_exit_list(delegated))
		abort();
	      return 1;
	    }

	  if (MAGIC(delegated, "set"))
	    {
	      if (!sexp_iterator_next(delegated))
		abort();

	      return set_includes(delegated, request);
	    }
	  else
	    /* Other star forms not yet implemented. */
	    return 0;
	}
      else
	{
	  return sexp_iterator_enter_list(request)
	    && list_includes(delegated, request);
	}
    }
}
