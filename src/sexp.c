/* sexp.c
 *
 * An implementation of Ron Rivest's S-expressions, used in spki.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "sexp.h"

#include "xalloc.h"

#define CLASS_DEFINE
#unclude "sexp.h.x"
#undef CLASS_DEFINE

struct lsh_string *do_format_sexp_string(struct sexp *s, int style)
{
  CAST(sexp_string, self, s);

  switch(style)
    {
    SEXP_TRANSPORT:
      return ssh_format("{%lfs}",
			encode_base64(SEXP_FORMAT(s, SEXP_CANONICAL), 1));
    case SEXP_ADVANCED:
      /* Special case of canonical, so we'll fal through for now. */
    case SEXP_CANONICAL:
      if (self->display)
	return ssh_format("[%ds]%ds",
			  self->display->length, self->display->data,
			  self->contents->length, self->contents->data);
      else
	return ssh_format("%ds",
			  self->contents->length, self->contents->data);
    default:
      fatal("do_format_sexp_string: Unknown output style.\n");
    }
}


      
		   
