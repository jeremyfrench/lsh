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


/* Memory allocation */
#define MALLOC(ctx, realloc, size) realloc((ctx), NULL, (size))

/* Cast needed because realloc doesn't like const pointers. */
#define FREE(ctx, realloc, p) realloc((ctx), (void *) (p), 0)

#define NEW(ctx, realloc, type, var) \
type *var = MALLOC(ctx, realloc, sizeof(type))


/* Strings */
struct spki_string
{
  unsigned refs;
  unsigned length;
  const uint8_t *data;
};

static struct spki_string *
spki_string_new(void *ctx, nettle_realloc_func *realloc,
		unsigned length, const uint8_t *data)
{
  NEW(ctx, realloc, struct spki_string, s);
  uint8_t *p;
  
  if (!s)
    return NULL;

  p = MALLOC(ctx, realloc, length);
  if (!p)
    {
      FREE(ctx, realloc, s);
      return NULL;
    }
  
  memcpy(p, data, length);
  s->refs = 1;
  s->length = length;
  s->data = p;

  return s;
}

static void
spki_string_release(void *ctx, nettle_realloc_func *realloc,
		    struct spki_string *s)
{
  if (!s)
    return;

  if (--s->refs)
    return;

  FREE(ctx, realloc, s->data);
  FREE(ctx, realloc, s);
}

static struct spki_string *
spki_string_dup(struct spki_string *s)
{
  assert(s);
  s->refs++;
  return s;
}


/* Lists */
struct spki_cons
{
  struct spki_tag *car;
  struct spki_cons *cdr;
};

/* Consumes the reference to CAR. Deallocates both CAR and CDR on
 * failure. */
static struct spki_cons *
spki_cons(void *ctx, nettle_realloc_func *realloc,
	  struct spki_tag *car, struct spki_cons *cdr)
{
  NEW(ctx, realloc, struct spki_cons, c);
  if (!c)
    {
      spki_tag_release(ctx, realloc, car);
      spki_cons_release(ctx, realloc, cdr);
      return NULL;
    }
  c->car = car;
  c->cdr = cdr;

  return c;
}

static void
spki_cons_release(void *ctx, nettle_realloc_func *realloc,
		  struct spki_cons *c)
{
  while (c)
    {
      struct spki_cons *cdr = c->cdr;
      spki_tag_release(ctx, realloc, c->car);
      FREE(ctx, realloc, c);
      c = cdr;
    }
}

/* Reverses a list destructively. */
static void
spki_cons_nreverse(struct spki_cons *c)
{
  struct spki_cons head = NULL;
  
  while (c)
    {
      struct spki_cons *next = c->cdr;
      
      /* Link current node at head */
      c->cdr = head;
      head = c;

      c = next;
    }

  return head;
}      


/* Tags abstraction */
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

struct spki_tag
{
  enum spki_tag_type type;
  unsigned refs;
};

static const struct spki_tag
spki_tag_any = { SPKI_TAG_ANY, 0 };

/* For SPKI_TAG_SET and SPKI_TAG_LIST */
struct spki_tag_list
{
  struct spki_tag super;
  struct spki_cons *children;
};

/* For SPKI_TAG_ATOM and SPKI_TAG_PREFIX */
struct spki_tag_atom
{
  struct spki_tag super;
  struct spki_string *display;
  struct spki_string *atom;
};

enum spki_range_type
  {
    SPKI_RANGE_TYPE_ALPHA,
    SPKI_RANGE_TYPE_NUMERIC,
    SPKI_RANGE_TYPE_TIME,
    SPKI_RANGE_TYPE_BINARY,
    SPKI_RANGE_TYPE_DATE,
    /* Indicates if the upper or lower limit is inclusive. */
    SPKI_RANGE_GTE = 0x10,
    SPKI_RANGE_LTE = 0x20
  };

/* For SPKI_TAG_RANGE */
struct spki_tag_range
{
  struct spki_tag super;
  enum spki_range_type flags;
  
  struct spki_string *display;
  struct spki_string *lower;
  struct spki_string *upper;
};

static void
spki_tag_init(struct spki_tag *tag,
	      enum spki_tag_type type)
{
  tag->type= type;
  tag->refs = 1;
}

static struct spki_tag *
spki_tag_dup(struct spki_tag *tag)
{
  assert(tag);
  if (tag != &spki_tag_any)
    tag->refs++;
  return tag;
}

static struct spki_tag *
spki_tag_atom_alloc(void *ctx, nettle_realloc_func *realloc,
		    enum spki_tag_type type,
		    struct sexp_iterator *i)
{
  struct spki_string *display;
  struct spki_string *atom;

  assert(i->type == SEXP_ATOM);
  assert(i->atom);

  if (i->display)
    {
      display = spki_string_new(ctx, realloc,
				i->display_length, i->display);

      if (!display)
	return NULL;
    }
  else
    display = NULL;
  
  atom = spki_string_new(ctx, realloc,
			 i->atom_length, i->atom);

  if (!atom)
    {
      spki_string_release(ctx, realloc, display);
      return NULL;
    }
  
  if (!sexp_iterator_next(i))
    {
      spki_string_release(ctx, realloc, display);
      spki_string_release(ctx, realloc, atom);
      return NULL;
    }
  
  {
    NEW(ctx, realloc, struct spki_tag_atom, tag);
    if (!tag)
      {
	spki_string_release(ctx, realloc, display);
	spki_string_release(ctx, realloc, atom);
	return NULL;
      }

    spki_tag_init(&tag->super, type);
    tag->display = display;
    tag->atom = atom;
    
    return &tag->super;
  }
}

static struct spki_tag *
spki_tag_list_alloc(void *ctx, nettle_realloc_func *realloc,
		    enum spki_tag_type type,
		    struct spki_cons *children)
{
  NEW(ctx, realloc, struct spki_tag_list, tag);

  assert(type == SPKI_TAG_SET || type == SPKI_TAG_LIST);
  
  if (tag)
    {
      spki_tag_init(&tag->super, type);
      tag->children = children;
    }

  return &tag->super;
}

static struct spki_tag *
spki_tag_range_alloc(void *ctx, nettle_realloc_func *realloc,
		     enum spki_range_type flags,
		     struct spki_string *display,
		     struct spki_string *lower,
		     struct spki_string *upper)
{
  NEW(ctx, realloc, struct spki_tag_range, tag);

  if (tag)
    {
      spki_tag_init(&tag->super, SPKI_TAG_RANGE);
      tag->flags = flags;
      tag->display = display;
      tag->lower = lower;
      tag->upper = upper;
    }

  return &tag->super;
}

void
spki_tag_release(void *ctx, nettle_realloc_func *realloc,
		 struct spki_tag *tag)
{
  if (!tag || tag == &spki_tag_any)
    return;

  assert(tag->refs);

  if (--tag->refs)
    return;

  switch(tag->type)
    {
    case SPKI_TAG_ATOM:
    case SPKI_TAG_PREFIX:
      {
	struct spki_tag_atom *self = (struct spki_tag_atom *) tag;

	spki_string_release(ctx, realloc, self->display);
	spki_string_release(ctx, realloc, self->atom);

	break;
      }
    case SPKI_TAG_LIST:
    case SPKI_TAG_SET:
      {
	struct spki_tag_list *self = (struct spki_tag_list *) tag;
	spki_cons_release(ctx, realloc, self->children);

	break;
      }
    case SPKI_TAG_RANGE:
      {
	struct spki_tag_range *self = (struct spki_tag_range *) tag;
	spki_string_release(ctx, realloc, self->lower);
	spki_string_release(ctx, realloc, self->upper);
      }
    default:
      abort();
    }

  FREE(ctx, realloc, tag);
}

/* Normalizes set expressions so that we always get
 *
 * (* set a b) rather than (* set (* set a) b)
 *
 * Requires that the children elements passet in are already
 * normalized.
 */

/* FIXME: A destructive function could be more efficient */
static struct spki_tag *
spki_tag_set_new(void *ctx, nettle_realloc_func *realloc,
		 struct sexp_cons *c)
{
  struct sexp_cons *subsets = NULL;
  struct sexp_tag *tag;
  
  for (; c; c = c->cdr)
    {
      if (c->car->type != SPKI_TAG_SET)
	{
	  subsets = spki_cons(ctx, realloc, spki_tag_dup(c->car), subsets);
	  if (!subsets)
	    return NULL;
	}
      else
	{
	  struct spki_tag_list *set = (struct spki_tag_list *) c->car;
	  struct spki_cons *p;
	  for (p = set->children; p; p = p->cdr)
	    {
	      /* Inner sets must be normalized. */
	      assert (p->car->type != SPKI_TAG_SET);
	      subsets = spki_cons(ctx, realloc, spki_tag_dup(p->car), subsets);
	      if (!subsets)
		return NULL;
	    }
	}
    }
  tag = spki_tag_list_alloc(ctx, realloc, SPKI_TAG_SET,
			    subsets);
  if (tag)
    return tag;

  spki_cons_release(ctx, realloc, subsets);
  return NULL;
}


/* Converting a tag into internal form */

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
      if (!sexp_iterator_enter_list(i)
	  || i->type != SEXP_ATOM)
	return 0;

      if (!i->display
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

static struct spki_cons *
spki_tag_compile_list(void *ctx, nettle_realloc_func *realloc,
		      struct sexp_iterator *i);

struct spki_tag *
spki_tag_compile(void *ctx, nettle_realloc_func *realloc,
		 struct sexp_iterator *i)
{
  enum spki_tag_type type = spki_tag_classify(i);
  
  switch (type)
    {
    default:
      return NULL;

    case SPKI_TAG_ATOM:
      return spki_tag_atom_alloc(ctx, realloc,
				 SPKI_TAG_ATOM, i);

    case SPKI_TAG_SET:
      {
	struct spki_tag *tag;
	struct spki_cons *children;
	
	/* Empty sets are allowed, but not empty lists. */
	if (i->type == SEXP_END)
	  return spki_tag_set_new(ctx, realloc, NULL);

	children = spki_tag_compile_list(ctx, realloc, i);

	if (!children)
	  return NULL;

	tag = spki_tag_set_new(ctx, realloc, children);
	spki_cons_release(ctx, realloc, children);

	return tag;
      }

    case SPKI_TAG_LIST:
      {
	struct spki_tag *tag;
	
	struct spki_cons *children
	  = spki_tag_compile_list(ctx, realloc, i);
	
	tag = spki_tag_list_alloc(ctx, realloc, type,
				  children);

	if (tag)
	  return tag;

	spki_cons_release(ctx, realloc, children);
	return NULL;
      }
      
    case SPKI_TAG_ANY:
      /* Cast to non-const, anybody that tries to modify it should
       * crash. */
      return (struct spki_tag *) &spki_tag_any;
      
    case SPKI_TAG_PREFIX:
      {
	struct spki_tag *tag = spki_tag_atom_alloc(ctx, realloc,
						   SPKI_TAG_PREFIX,
						   i);
	if (!tag)
	  return NULL;

	if (i->type == SEXP_END && sexp_iterator_exit_list(i))
	  return tag;

	spki_tag_release(ctx, realloc, tag);
	return NULL;
      }

    case SPKI_TAG_RANGE:
      /* Not yet implemented. */
      abort();
    }

}

/* NOTE: Conses the list up in reverse order. */
static struct spki_cons *
spki_tag_compile_list(void *ctx, nettle_realloc_func *realloc,
		      struct sexp_iterator *i)
{
  struct spki_cons *c = NULL;

  while (i->type != SEXP_END)
    {
      struct spki_tag *tag = spki_tag_compile(ctx, realloc, i);
      struct spki_cons *n;
      
      if (!tag)
	{
	  spki_cons_release(ctx, realloc, c);
	  return NULL;
	}
      n = spki_cons(ctx, realloc, tag, c);
      if (!n)
	/* spki_cons has already released both tag and c */
	return NULL;
	
      c = n;
    }

  if (!sexp_iterator_exit_list(i))
    {
      spki_cons_release(ctx, realloc, c);
      return NULL;
    }
  return c;
}


/* Tag operations */

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
set_includes(struct sexp_iterator *delegated,
	     struct sexp_iterator *request)
{
  /* The request is included if it's including in any of
   * the delegations in the set. */
  unsigned level = delegated->level;

  while (delegated->type != SEXP_END)
    {
      struct sexp_iterator work = *request;
      unsigned start = delegated->start;
      
      if (spki_tag_includes(delegated, &work))
	{
	  if (!sexp_iterator_exit_list(delegated))
	    abort();
	  *request = work;
	  return 1;
	}
      /* It's a little tricky to recover. When trying to match the
       * tag, matching may have given up with the iterator pointing
       * anywhere inside it. We first need to skip out of some lists,
       * and then make sure that we have made some advance, to cover
       * the case that the previous sub expression was a string. */
      /* FIXME: Make some iterator abstraction for this. */
      assert(delegated->level >= level);

      while (delegated->level > level)
	if (!sexp_iterator_exit_list(delegated))
	  abort();

      if (delegated->start == start &&
	  !sexp_iterator_next(delegated))
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
 * Compares only the first element on each list and, on success,
 * advances the corresponding iterator past it.
 */
/* FIXME: It's a problem that both syntax errors and matching failures
 * are reported in the same way. */
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
      return sexp_iterator_next(request);

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
