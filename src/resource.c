/* resource.c
 *
 * External resources associated with a connection, for instance
 * processes and ports. Used to kill or release the resource in
 * question when the connection dies.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "resource.h"

#include "werror.h"
#include "xalloc.h"

/* Prototypes */
void do_mark_resources(struct resource_node *n,
		       void (*mark)(struct lsh_object *o));

void do_free_resources(struct resource_node *n);
void dont_free_live_resource(int alive);

#define CLASS_DEFINE
#include "resource.h.x"
#undef CLASS_DEFINE

void do_mark_resources(struct resource_node *n,
		       void (*mark)(struct lsh_object *o))
{
  for(; n; n = n->next)
    mark(&n->resource->super);
}

void do_free_resources(struct resource_node *n)
{
  while(n)
    {
      struct resource_node *old = n;

      n = n->next;
      lsh_space_free(old);
    }
}

void dont_free_live_resource(int alive)
{
  if (alive)
    fatal("dont_free_live_resource: About to garbage collect a live resource!\n");
}

static struct resource_node *do_remember_resource(struct resource_list *self,
						  struct resource *r)
{
  struct resource_node *n;

  NEW_SPACE(n);
  n->resource = r;

  /* Add at head of list */
  n->next = self->head;
  n->prev = NULL;
  self->head = n;

  if (n->next)
    n->next->prev = n;
  else
    self->tail = n;

  return n;
}

static void do_kill_all(struct resource_list *self)
{
  /* FIXME: Doesn't deallocate any nodes */
  struct resource_node *n;

  for (n = self->head; n; n = n->next)
    KILL_RESOURCE(n->resource);
}
  
struct resource_list *empty_resource_list(void)
{
  NEW(resource_list, self);
  self->head = self->tail = NULL;

  self->remember = do_remember_resource;
  self->kill_all = do_kill_all;
  /* self->kill = do_kill_resource; */

  return self;
}
