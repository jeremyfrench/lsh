/* tag.h
 *
 * Operations on SPKI "tags", i.e. authorization descriptions. */

/* libspki
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#ifndef LIBSPKI_TAG_H_INCLUDED
#define LIBSPKI_TAG_H_INCLUDED

struct sexp_iterator;

/* Returns true if the requested authorization is included in the
 * delegated one. For now, star forms are recognized only in the
 * delegation, not in the request. */
int
spki_tag_includes(struct sexp_iterator *delegated,
		  struct sexp_iterator *request);

#endif /* LIBSPKI_TAG_H_INCLUDED */

