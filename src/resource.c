/* resource.c
 *
 * External resources associated with a connection, for instance
 * processes and ports. Used to kill or release the resource in
 * question when the connection dies.
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "resource.h"

#include "gc.h"
#include "werror.h"
#include "xalloc.h"


/* Forward declarations */
void dont_free_live_resource(int alive);

void do_mark_resources(struct resource_node **q,
		       void (*mark)(struct lsh_object *o));

void do_free_resources(struct resource_node **q);

#define GABA_DEFINE
#include "resource.h.x"
#undef GABA_DEFINE


/* Sanity check */

void
dont_free_live_resource(int alive)
{
  if (alive)
    fatal("dont_free_live_resource: "
          "garbage collecting a live resource!\n");
}

/* For resources that are only marked as dead, and taken care of
 * later. */
static void
do_resource_kill(struct resource *self)
{ self->alive = 0; }

void
init_resource(struct resource *self,
	      void (*k)(struct resource *))
{
  self->alive = 1;
  self->kill = k ? k : do_resource_kill;
}

/* The behaviour of a resource list is somewhat similar to
 * a weak list. Nodes that are dead are unlinked automatically,
 * so that they can be garbage collected. */

struct resource_node
{
  struct resource_node *next;
  struct resource *resource;
};

/* Loop over the resources, process the living and unlink the dead. */
static void
resource_iterate(struct resource_node **q,
		 void (*f)(struct resource *r))
{
  struct resource_node *n;

  while ( (n = *q) )
    {
      if (n->resource->alive)
	f(n->resource);

      if (n->resource->alive)
	q = &n->next;
      else
	{
	  *q = n->next;
	  lsh_space_free(n);
	}
    }
}

/* Mark the live resources. */
void
do_mark_resources(struct resource_node **q,
		  void (*mark)(struct lsh_object *o))
{
  resource_iterate(q, (void (*)(struct resource *r)) mark);
}

/* Free the list. */
void
do_free_resources(struct resource_node **q)
{
  struct resource_node *n;

  for (n = *q; n; )
    {
      struct resource_node *old = n;
      n = n->next;
      lsh_space_free(old);
    }
}

void
resource_list_foreach(struct resource_list *self,
		      void (*f)(struct resource *r))
{
  resource_iterate(&self->q, f);
}

/* Returns the first live resource on the list. Also unlinks any dead
   resources found. */
struct resource *
resource_list_top(struct resource_list *self)
{
  for (; self->q; self->q = self->q->next)
    if (self->q->resource->alive)
      return self->q->resource;

  return NULL;
}

void
remember_resource(struct resource_list *self,
		  struct resource *resource)
{
  struct resource_node *n;

  assert(resource);
  
  if (!self->super.alive)
    {
      werror("do_remember_resource: resource list is already dead.\n");
      KILL_RESOURCE(resource);
      return;
    }
  
  NEW_SPACE(n);

  n->resource = resource;
  n->next = self->q;
  self->q = n;
}

static void
kill_resource(struct resource *resource)
{
  KILL_RESOURCE(resource);
}

static void
do_kill_resource_list(struct resource *s)
{
  CAST(resource_list, self, s);

  trace("do_kill_resource_list: resource_list %xi\n", self);

  if (self->super.alive)
    {
      self->super.alive = 0;

      resource_list_foreach(self, kill_resource);
    }
}

struct resource_list *
make_resource_list(void)
{
  NEW(resource_list, self);
  init_resource(&self->super, do_kill_resource_list);

  trace("make_resource_list: created %xi\n", self);
  
  self->q = NULL;

  return self;
}

/* Are there any live resources on the list? */
int
resource_list_is_empty(struct resource_list *self)
{
  struct resource_node *n;

  assert(self->super.alive);
  for (n = self->q; n; )
    {
      CAST_SUBTYPE(resource, r, n->resource);
      if (r->alive)
	return 0;
    }
  return 1;
}
