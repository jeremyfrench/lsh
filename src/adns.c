/* adns.c
 *
 * interface to Ian Jackson's asynchronous resolver.
 * 
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balázs Scheidler, Niels Möller
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

#include "io.h"

#include "werror.h"
#include "xalloc.h"

#include <adns.h>

/* Forward declarations */
static void
do_adns_mark(adns_state s,
	     void (*mark)(struct lsh_object *o));
static void
do_adns_free(adns_state s);

#include "adns.c.x"

/* Stuff that should move to io.h/io.c when ready */

/* GABA:
   (class
     (name address_info)
     (vars
       ; An ipnumber, in decimal dot notation, ipv6 format, or
       ; a dns name.
       (host string)
       ; The port number here is always in host byte order
       (port . UINT32)
       ; Raw address
       (socket space "struct sockaddr")))
*/

/* GABA:
   (class
     (name io_special)
     (vars
       ; Number of interesting fds
       (nfds . unsigned)
       ; Figure out number of fds, and next timeout
       (prepare method void ...)
       (before method void "struct pollfd *")
       (after method void "const struct pollfd *")))
*/

/* GABA:
   (class
     (name resolver)
     (super io_special)
     (vars
       (adns special adns_state
             adns_mark adns_free)))
*/

static void
do_resolver_after(struct io_special *s)
{
  CAST(resolver, self, s);

  adns_query q = NULL;
  adns_answer *answer;
  void *c;
  adns_afterpoll(self->adns, ...);

  while (!adns_check(self->adns, &q,
		     &answer, &c))
    {
      CAST(resolver_context, ctx, c);
      switch (answer->status)
	{
	}
    }
}

struct command *
make_resolver(void)
{
  NEW(resolver, self);
  int res;
  
  if ( (res = adns_init(&self->adns, flags, NULL)) )
    {
      werror("adns_init failed (errno = %i): %z", res, strerror(res));
      KILL(self);
      return NULL;
    }

  return &self->super;
}

/* GABA:
   (class
     (name resolver_context)
     (super command_context)
     (vars
       (address object address_info)))
*/

/* GABA:
   (class
     (name resolver_command)
     (super command)
     (vars
       (resolver object resolver)))
*/

/* Resolve a literal IPv4 or IPv6 address */
static void
do_resolve_numeric(struct command *s,
		   struct lsh_object *x,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(resolver_command, self, s);
  CAST(address_info, a, x);

  assert(!a->socket);
  
}

/* Resolve a dns name or a literal IPv4 or IPv6 address */
static void
do_resolve(struct command *s,
	   struct lsh_object *x,
	   struct command_continuation *c,
	   struct exception_handler *e)
{
  CAST(resolver_command, self, s);
  CAST(address_info, a, x);
  adns_query q;
  
  assert(!a->socket);

  /* FIXME: Check literal address first. */

  assert(NUL_TERMINATED(a->host));
  adns_submit(self->resolver->adns,
	      a->host->data,
	      adns_r_addr,
	      0, /* adns_queryflags, could use IPv6-related flags */
	      make_resolver_context(a, c, e),
	      &q);
}

static void
do_adns_mark(adns_state s,
	     void (*mark)(struct lsh_object *o))
{
  adns_query q;
  void *ctx;
  
  adns_forallqueries_begin(s);
  
  while( (q = adns_forallqueries_next(s, &ctx)) )
    mark( (struct lsh_object *) ctx);
}

static void
do_adns_free(adns_state s)
{
  adns_forallqueries_begin(s);

  if (adns_forallqueries_next(s, NULL))
    werror("Dropping queries on the floor.\n");

  adns_finish(s);
}



	     
