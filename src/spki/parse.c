/* parse.c */

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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "parse.h"
#include "nettle/sexp.h"

#include "string.h"

/* Automatically generated files */

/* FIXME: Is there any way to get gperf to declare this function
 * static? */
const struct spki_assoc *
spki_gperf (const char *str, unsigned int len);

#include "spki-gperf.h"

enum spki_type
spki_intern(struct sexp_iterator *i)
{  
  if (i->type == SEXP_ATOM
      && !i->display)
    {
      const struct spki_assoc *assoc = spki_gperf(i->atom, i->atom_length);

      if (assoc && sexp_iterator_next(i))
	return assoc->id;
    }
  
  return 0;
}

/* NOTE: Uses SPKI_TYPE_UNKNOWN (= 0) for both unknown types and
 * syntax errors. */
enum spki_type
spki_parse_type(struct sexp_iterator *i)
{
  if (i->type == SEXP_END)
    return SPKI_TYPE_END_OF_EXPR;

  return sexp_iterator_enter_list(i) ? spki_intern(i) : 0;
}


/* These parsing functions should be called with an iterator pointing
 * into the body of the expression being parsed, just after the
 * type.
 *
 * On success, the parsing function should exit the current
 * expression, and return the type of the next expression in the
 * containing list.
 */

enum spki_type
spki_parse_end(struct sexp_iterator *i)
{
  return (i->type == SEXP_END
	  && sexp_iterator_exit_list(i)) ? spki_parse_type(i) : 0;
}

enum spki_type
spki_parse_principal(struct spki_acl_db *db, struct sexp_iterator *i,
		     struct spki_principal **principal)
{
  struct sexp_iterator before = *i;

  switch (spki_parse_type(i))
    {
    default:
      return 0;

    case SPKI_TYPE_PUBLIC_KEY:
      {
	const uint8_t *key;
	unsigned key_length;
	enum spki_type next;
	
	*i = before;
	key = sexp_iterator_subexpr(i, &key_length);
	
	if (!key)
	  return 0;

	next = spki_parse_type(i);
	if (!next)
	  return 0;

	return (*principal = spki_principal_by_key(db, key_length, key))
	  ? next : 0;
      }

    case SPKI_TYPE_HASH:
      {
	enum spki_type type = spki_intern(i);

	if (type
	    && i->type == SEXP_ATOM
	    && !i->display)
	  {
	    enum spki_type next;
	    unsigned digest_length = i->atom_length;
	    const uint8_t *digest = i->atom;
	    
	    if (sexp_iterator_next(i) && (next = spki_parse_end(i)))
	      {
		if (type == SPKI_TYPE_MD5
		    && digest_length == MD5_DIGEST_SIZE)
		  *principal = spki_principal_by_md5(db, digest);

		else if (type == SPKI_TYPE_SHA1
			 && digest_length == SHA1_DIGEST_SIZE)
		  *principal = spki_principal_by_sha1(db, digest);
		else
		  return 0;

		return next;
	      }
	  }
	return 0;
      }
    } 
}
