/* parse.h */

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

#ifndef LIBSPKI_PARSE_H_INCLUDED
#define LIBSPKI_PARSE_H_INCLUDED

#include "certificate.h"


enum spki_type
spki_intern(struct sexp_iterator *i);

enum spki_type
spki_parse_type(struct sexp_iterator *i);

enum spki_type
spki_parse_end(struct sexp_iterator *i);

enum spki_type
spki_parse_skip(struct sexp_iterator *i);

enum spki_type
spki_parse_principal(struct spki_acl_db *db, struct sexp_iterator *i,
		     struct spki_principal **principal);

enum spki_type
spki_parse_tag(struct spki_acl_db *db, struct sexp_iterator *i,
	       struct spki_5_tuple *tuple);

enum spki_type
spki_parse_date(struct sexp_iterator *i,
		struct spki_date *d);

enum spki_type
spki_parse_valid(struct sexp_iterator *i,
		 struct spki_5_tuple *tuple);

enum spki_type
spki_parse_version(struct sexp_iterator *i);

enum spki_type
spki_parse_acl_entry(struct spki_acl_db *db, struct sexp_iterator *i,
		     struct spki_5_tuple *acl);

enum spki_type
spki_parse_cert(struct spki_acl_db *db, struct sexp_iterator *i,
		struct spki_5_tuple *cert);

#endif /* LIBSPKI_PARSE_H_INCLUDED */
