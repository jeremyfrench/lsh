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

static void
do_default_handler(struct exception_handler *ignored UNUSED,
		   struct exception *e)
{
#if 0
  if (e->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, io, e);
      werror("i/o error (errno = %i): %z\n", io->error, e->name);
      
      if (io->fd)
	kill_fd(io->fd);
    }
  else
#endif
    fatal("Unhandled exception of type: %z\n", e->type, e->name);
}

struct exception_handler default_exception_handler =
{ STATIC_HEADER, do_default_handler };

struct exception dummy_exception =
{ STATIC_HEADER, LSH_DUMMY, "dummy" };

static void
do_ignore_exception_handler(struct exception_handler *self UNUSED,
			    struct exception *e UNUSED)
{}

struct exception_handler ignore_exception_handler =
{ STATIC_HEADER, do_ignore_exception_handler };


struct exception *make_simple_exception(UNIT32 type, const char *name)
{
  NEW(exception, e);
  e->type = type;
  e->name = name;
}

struct exception *
make_protocol_exception(UINT32 reason, const char *msg)
{
  NEW(protocol_exception, self);

#define MAX_REASON 11
  const char *messages[MAX_REASON+1] =
  {
    "", "Host not allowed to connect",
    "Protocol error", "Key exchange failed",
    "Host authentication failed", "MAC error",
    "Compression error", "Service not available",
    "Protocol version not supported", "Host key not verifiable",
    "Connection lost", "By application"
  };
    
  assert(reason >= 0);
  assert(reason <= MAX_REASON);

#undef MAX_REASON

  self->super.type = EXC_PROTOCOL;
  self->super.name = msg ? msg : messages[reason];

  self->reason = reason;

  return &self->super;
}
