/* queue.c
 *
 * $Id$
 *
 * Generic doubly linked list. */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "queue.h"

#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* Prototypes */
static void do_object_queue_mark(struct lsh_queue *q,
			  void (*mark)(struct lsh_object *o));
static void do_object_queue_free(struct lsh_queue *q);

#define GABA_DEFINE
#include "queue.h.x"
#undef GABA_DEFINE

/* Short cuts */
#define next np_links[LSH_QUEUE_NEXT]
#define prev np_links[LSH_QUEUE_PREV]

#define head ht_links[LSH_QUEUE_HEAD]
#define tail ht_links[LSH_QUEUE_TAIL]
#define tailprev ht_links[LSH_QUEUE_TAILPREV]

#define EMPTYP(q) ((q)->tailprev == (struct lsh_queue_node *) (q))

#if DEBUG_ALLOC
static void sanity_check_queue(struct lsh_queue *q)
{
  struct lsh_queue_node *n;

#if 0
  debug("sanity_check_queue: q = %xi\n", (UINT32) q);
#endif
  if (q->tail)
    fatal("sanity_check_queue: q->tail not NULL!\n");

  n = q->head;

  if (n->prev != (struct lsh_queue_node *) q)
    fatal("sanity_check_queue: head->next != &q->head !\n");

  while (n->next)
    {
#if 0
      debug("  n = %xi\n", (UINT32) n);
#endif 
      if (n->prev->next != n)
	fatal("n->prev->next != n !\n");

      n = n->next;
    }
  if (n != (struct lsh_queue_node *) &(q->tail))
    fatal("n != n &t->tail!\n");
}
#else
#define sanity_check_queue(x)
#endif

void lsh_queue_init(struct lsh_queue *q)
{
  q->head = (struct lsh_queue_node *) &(q->tail);
  q->tail = NULL;
  q->tailprev = (struct lsh_queue_node *) &(q->head);
  sanity_check_queue(q);
}

int lsh_queue_is_empty(struct lsh_queue *q)
{
  sanity_check_queue(q);
  return EMPTYP(q);
}

void lsh_queue_add_head(struct lsh_queue *q, struct lsh_queue_node *n)
{
  sanity_check_queue(q);
  n->next = q->head;
  n->prev = (struct lsh_queue_node *) &(q->head);
  n->prev->next = n;
  n->next->prev = n;
  sanity_check_queue(q);
}

void lsh_queue_add_tail(struct lsh_queue *q, struct lsh_queue_node *n)
{
  sanity_check_queue(q);
  n->next = (struct lsh_queue_node *) &(q->tail);
  n->prev = q->tailprev;
  n->prev->next = n;
  n->next->prev = n;
  sanity_check_queue(q);
}

void lsh_queue_remove(struct lsh_queue_node *n)
{
  assert(n->next);
  assert(n->prev);
  n->next->prev = n->prev;
  n->prev->next = n->next;
}

struct lsh_queue_node *lsh_queue_remove_head(struct lsh_queue *q)
{
  struct lsh_queue_node *n = q->head;

  sanity_check_queue(q);
  assert(!EMPTYP(q));
  lsh_queue_remove(n);
  sanity_check_queue(q);

  return n;
}

struct lsh_queue_node *lsh_queue_remove_tail(struct lsh_queue *q)
{
  struct lsh_queue_node *n = q->tailprev;
  
  sanity_check_queue(q);
  assert(!EMPTYP(q));
  lsh_queue_remove(n);
  sanity_check_queue(q);

  return n;
}

/* Object queue */
struct object_queue_node
{
  struct lsh_queue_node header;
  struct lsh_object *o;
};


static struct object_queue_node *
make_object_queue_node(struct lsh_object *o)
{
  struct object_queue_node *n;

  NEW_SPACE(n);
  n->o = o;

  return n;
}

void object_queue_add_head(struct object_queue *q, struct lsh_object *o)
{
  lsh_queue_add_head(&q->q, &make_object_queue_node(o)->header);
}

void object_queue_add_tail(struct object_queue *q, struct lsh_object *o)
{
  lsh_queue_add_tail(&q->q, &make_object_queue_node(o)->header);
}

static struct lsh_object *
object_queue_get_contents(struct object_queue_node *n)
{
  struct lsh_object *res = n->o;
  lsh_space_free(n);

  return res;
}

struct lsh_object *object_queue_remove_head(struct object_queue *q)
{
  return object_queue_get_contents((struct object_queue_node *)
				   lsh_queue_remove_head(&q->q));
}

struct lsh_object *object_queue_remove_tail(struct object_queue *q)
{
  return object_queue_get_contents((struct object_queue_node *)
				   lsh_queue_remove_tail(&q->q));
}

/* For gc */
static void do_object_queue_mark(struct lsh_queue *q,
				 void (*mark)(struct lsh_object *o))
{
  FOR_QUEUE(q, struct object_queue_node *, n)
    mark(n->o);
}

static void do_object_queue_free(struct lsh_queue *q)
{
  FOR_QUEUE(q, struct object_queue_node *, n)
    lsh_space_free(n);
}

  
