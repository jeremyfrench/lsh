/* userauth.h
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_USERAUTH_H_INCLUDED
#define LSH_USERAUTH_H_INCLUDED

#include "lsh_types.h"

/* Returns 0 if the request is somehow invalid. Otheerwise, returns 1,
 * and sets SERVICE non-NULL iff access is granted. */

/* FIXME: Something more general is needed for authentication methods
 * which send additional messages. */
struct userauth
{
  struct lsh_object header;
  
  int (*authenticate)(struct userauth *self,
		      lsh_string *user,
		      int requested_service,
		      struct simple_buffer *args,
		      struct ssh_service **service);
};

#define AUTHENTICATE(s, u, r, a, g) \
((s)->authenticate((s), (u), (r), (a), (g)))
     
#endif /* LSH_USERAUTH_H_INCLUDED */
