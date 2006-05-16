/* exception.c
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

#include "exception.h"

#include "io.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "exception.h.x"
#undef GABA_DEFINE

DEFINE_EXCEPTION_HANDLER(ignore_exception_handler)
     (struct exception_handler *self UNUSED,
      const struct exception *e)
{
  trace("Ignoring exception: %z (type %i:%i)\n",
	e->msg, e->type, e->subtype);
}

struct exception *
make_exception(int type, int subtype, const char *msg)
{
  NEW(exception, e);
  e->type = type;
  e->subtype = subtype;
  e->msg = msg;

  return e;
}

#if DEBUG_TRACE
void
exception_raise(struct exception_handler *h,
		const struct exception *e,
		const char *context)
{
  trace ("%z: Raising exception %z (type %i:%i), using handler installed by %z\n",
	 context, e->msg, e->type, e->subtype, h->context);
  h->raise(h, e);
}
#endif /* DEBUG_TRACE */
