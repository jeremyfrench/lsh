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
#include "spki-types.h"

#include "nettle/sexp.h"

struct spki_iterator
{
  /* When a parsing function is invoked, the sexp_iterator points into
   * the body of the expression being parsed, just after the type.
   * Type is an interned representation fo the expresssion type, and start
   * is the position of the first byte of the expression. For example,
   *
   *     (foo x y z)
   *     ^ ^  ^
   *     | |  i->sexp
   *     | i->type
   *     i->start
   */
  
  struct sexp_iterator sexp;

  /* Type of the current expression */
  enum spki_type type;

  /* Start of the most recently entered expression */
  unsigned start;
};

enum spki_type
spki_iterator_first(struct spki_iterator *i,
		    unsigned length, const uint8_t *expr);

enum spki_type
spki_iterator_first_sexp(struct spki_iterator *i,
			 const struct sexp_iterator *sexp);

enum spki_type
spki_intern(struct spki_iterator *i);

const uint8_t *
spki_parse_prevexpr(struct spki_iterator *i,
		    unsigned start, unsigned *length);

enum spki_type
spki_parse_type(struct spki_iterator *i);

/* FIXME: Implement and make use of this function. */
#if 0
int
spki_check_type(struct spki_iterator *i, enum spki_type type);
#endif

enum spki_type
spki_parse_end(struct spki_iterator *i);

enum spki_type
spki_parse_skip(struct spki_iterator *i);

enum spki_type
spki_parse_principal(struct spki_acl_db *db, struct spki_iterator *i,
		     struct spki_principal **principal);

enum spki_type
spki_parse_subject(struct spki_acl_db *db, struct spki_iterator *i,
		   struct spki_principal **principal);

enum spki_type
spki_parse_issuer(struct spki_acl_db *db, struct spki_iterator *i,
		  struct spki_principal **principal);

enum spki_type
spki_parse_tag(struct spki_acl_db *db, struct spki_iterator *i,
	       struct spki_tag **tag);

enum spki_type
spki_parse_date(struct spki_iterator *i,
		struct spki_date *d);

enum spki_type
spki_parse_valid(struct spki_iterator *i,
		 struct spki_5_tuple *tuple);

enum spki_type
spki_parse_version(struct spki_iterator *i);

enum spki_type
spki_parse_acl_entry(struct spki_acl_db *db, struct spki_iterator *i,
		     struct spki_5_tuple *acl);

enum spki_type
spki_parse_cert(struct spki_acl_db *db, struct spki_iterator *i,
		struct spki_5_tuple *cert);

#endif /* LIBSPKI_PARSE_H_INCLUDED */
