/* charset.h
 *
 * Translate local characterset to and from utf8.
 *
 * $Id$
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

#ifndef LSH_CHARSET_H_INCLUDED
#define LSH_CHARSET_H_INCLUDED

#include "lsh_types.h"

/* FIXME: Use charsets real objects, instead of using fixed constants */

#define CHARSET_UTF8 0
#define CHARSET_LATIN1 1
#define CHARSET_USASCII 2

void set_local_charset(int charset);

UINT32 local_to_ucs4(int c);
int ucs4_to_local(UINT32 c);

struct lsh_string *local_to_utf8(struct lsh_string s, int free);
struct lsh_string *utf8_to_local(struct lsh_string s, int free);

#endif /* LSH_CHARSET_H_INCLUDED */
