/* exception.c
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

#include "exception.h"

#include "io.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "exception.h.x"
#undef GABA_DEFINE

static void
do_default_handler(struct exception_handler *ignored UNUSED,
		   const struct exception *e)
{
#if 0
  if (e->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, io, e);
      werror("i/o error (errno = %i): %z\n", io->error, e->msg);
      
      if (io->fd)
	kill_fd(io->fd);
    }
  else
#endif
    fatal("Unhandled exception of type %xi: %z\n", e->type, e->msg);
}

struct exception_handler default_exception_handler =
{ STATIC_HEADER, do_default_handler };

struct exception dummy_exception =
{ STATIC_HEADER, EXC_DUMMY, "dummy" };

static void
do_ignore_exception_handler(struct exception_handler *self UNUSED,
			    const struct exception *e UNUSED)
{}

struct exception_handler ignore_exception_handler =
{ STATIC_HEADER, do_ignore_exception_handler };

struct exception_handler *
make_exception_handler(void (*raise)(struct exception_handler *s,
				     const struct exception *x),
		       struct exception_handler *parent)
{
  NEW(exception_handler, self);
  self->raise = raise;
  self->parent = parent;

  return self;
}

struct exception *make_simple_exception(UINT32 type, const char *msg)
{
  NEW(exception, e);
  e->type = type;
  e->msg = msg;

  return e;
}

/* Reason == 0 means disconnect without sending any disconnect
 * message. */

struct exception *
make_protocol_exception(UINT32 reason, const char *msg)
{
  NEW(protocol_exception, self);

#define MAX_REASON 11
  const char *messages[MAX_REASON+1] =
  {
    NULL, "Host not allowed to connect",
    "Protocol error", "Key exchange failed",
    "Host authentication failed", "MAC error",
    "Compression error", "Service not available",
    "Protocol version not supported", "Host key not verifiable",
    "Connection lost", "By application"
  };
    
  assert(reason <= MAX_REASON);

#undef MAX_REASON

  self->super.type = EXC_PROTOCOL;
  self->super.msg = msg ? msg : messages[reason];

  self->reason = reason;

  return &self->super;
}
