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
#include "tag.h"

#include "nettle/sexp.h"

#include <assert.h>
#include <string.h>

/* Automatically generated files */

/* FIXME: Is there any way to get gperf to declare this function
 * static? */
const struct spki_assoc *
spki_gperf (const char *str, unsigned int len);

#include "spki-gperf.h"

enum spki_type
spki_intern(struct spki_iterator *i)
{  
  if (i->sexp.type == SEXP_ATOM
      && !i->sexp.display)
    {
      const struct spki_assoc *assoc
	= spki_gperf(i->sexp.atom, i->sexp.atom_length);

      if (assoc && sexp_iterator_next(&i->sexp))
	return assoc->id;
    }
  
  return 0;
}

/* NOTE: Uses SPKI_TYPE_SYNTAX_ERROR (= 0) for both unknown types and
 * syntax errors. */
enum spki_type
spki_parse_type(struct spki_iterator *i)
{
  i->start = i->sexp.start;
  switch(i->sexp.type)
    {
    case SEXP_END:
      i->type = SPKI_TYPE_END_OF_EXPR;
      break;

    case SEXP_LIST:
      i->type = (sexp_iterator_enter_list(&i->sexp))
	? spki_intern(i) : 0;
      
      break;

    case SEXP_ATOM:
      i->type = 0;
      break;
    }
  return i->type;
}

enum spki_type
spki_iterator_first(struct spki_iterator *i,
		    unsigned length, const uint8_t *expr)
{
  i->start = 0;
  if (sexp_iterator_first(&i->sexp, length, expr))
    return spki_parse_type(i);

  i->type = 0;
  return 0;
}

enum spki_type
spki_iterator_first_sexp(struct spki_iterator *i,
			 const struct sexp_iterator *sexp)
{
  i->start = 0;
  i->sexp = *sexp;

  return spki_parse_type(i);
}

enum spki_type
spki_parse_end(struct spki_iterator *i)
{
  return (i->type && i->sexp.type == SEXP_END
	  && sexp_iterator_exit_list(&i->sexp)) ? spki_parse_type(i) : 0;
}

enum spki_type
spki_parse_skip(struct spki_iterator *i)
{
  return sexp_iterator_exit_list(&i->sexp) ? spki_parse_type(i) : 0;
}

const uint8_t *
spki_parse_prevexpr(struct spki_iterator *i,
		    unsigned start, unsigned *length)
{
  assert(start < i->start);
  *length = i->start - start;
  return i->sexp.buffer + start;
}

static const uint8_t *
spki_parse_string(struct spki_iterator *i,
		  unsigned *length)
{
  if (i->sexp.type == SEXP_ATOM
      && ! i->sexp.display)
    {
      const uint8_t *contents = i->sexp.atom;
      *length = i->sexp.atom_length;
      
      if (sexp_iterator_next(&i->sexp))
	return contents;
    }
  return NULL;
}

enum spki_type
spki_parse_principal(struct spki_acl_db *db, struct spki_iterator *i,
		     struct spki_principal **principal)
{
  switch (spki_parse_type(i))
    {
    default:
      return 0;

    case SPKI_TYPE_PUBLIC_KEY:
      {
	unsigned start = i->start;

	unsigned key_length;
	const uint8_t *key;
	enum spki_type next;
	
	next = spki_parse_skip(i);
	if (!next)
	  return 0;

	key = spki_parse_prevexpr(i, start, &key_length);

	assert(key);

	return (*principal = spki_principal_by_key(db, key_length, key))
	  ? next : 0;
      }

    case SPKI_TYPE_HASH:
      {
	enum spki_type type = spki_intern(i);
	unsigned digest_length;
	const uint8_t *digest;
	enum spki_type next;
	
	if (type
	    && (digest = spki_parse_string(i, &digest_length))
	    && (next = spki_parse_end(i)))
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
	return 0;
      }
    } 
}

enum spki_type
spki_parse_tag(struct spki_acl_db *db, struct spki_iterator *i,
	       struct spki_tag **tag)
{
  enum spki_type next;

  assert(i->type == SPKI_TYPE_TAG);
  
  return ((*tag = spki_tag_compile(db->realloc_ctx, db->realloc,
				   &i->sexp))
	  && (next = spki_parse_end(i)));
}

enum spki_type
spki_parse_date(struct spki_iterator *i,
		struct spki_date *d)
{
  unsigned date_length;
  const uint8_t *date_string;
  enum spki_type next;
  
  if ((date_string = spki_parse_string(i, &date_length))
      && date_length == SPKI_DATE_SIZE
      && date_string[4] == '-'
      && date_string[7] == '-'
      && date_string[10] == '_'
      && date_string[13] == ':'
      && date_string[16] == ':'
      && (next = spki_parse_end(i))) 
    {
      memcpy(d->date, date_string, SPKI_DATE_SIZE);
      return next;
    }
  return 0;
}

enum spki_type
spki_parse_valid(struct spki_iterator *i,
		 struct spki_5_tuple *tuple)
{
  assert(i->type == SPKI_TYPE_VALID);
  
  spki_parse_type(i);

  if (i->type == SPKI_TYPE_NOT_BEFORE)
    {
      if (spki_parse_date(i, &tuple->not_before))
	tuple->flags |= SPKI_NOT_BEFORE;
    }

  if (i->type == SPKI_TYPE_NOT_AFTER)
    {
      if (spki_parse_date(i, &tuple->not_after))
	tuple->flags |= SPKI_NOT_AFTER;
    }

  /* Online tests not supported. */
  return spki_parse_end(i);  
}

static int
spki_parse_uint32(struct spki_iterator *i, uint32_t *x)
{
  return sexp_iterator_get_uint32(&i->sexp, x);
}

/* Requires that the version number be zero. */
enum spki_type
spki_parse_version(struct spki_iterator *i)
{
  uint32_t version;
  assert(i->type == SPKI_TYPE_VERSION);
  
  return (spki_parse_uint32(i, &version)
	  && version == 0)
    ? spki_parse_end(i) : 0;
}

/* The acl must already be initialized. */
enum spki_type
spki_parse_acl_entry(struct spki_acl_db *db, struct spki_iterator *i,
		     struct spki_5_tuple *acl)
{
  /* Syntax:
   *
   * ("entry" <principal> <delegate>? <tag> <valid>? <comment>?) */

  assert(i->type == SPKI_TYPE_ENTRY);

  spki_parse_type(i);
  
  /* NOTE: draft-ietf-spki-cert-structure-06.txt has a raw <subj-obj>,
   * but that should be changed. */
  if (i->type != SPKI_TYPE_SUBJECT)
    return 0;

  /* FIXME: Write an spki_parse_subject function. */
  if (! (spki_parse_principal(db, i, &acl->subject)
	 && spki_parse_end(i)))
    return 0;

  if (i->type == SPKI_TYPE_PROPAGATE)
    {
      acl->flags |= SPKI_PROPAGATE;
      spki_parse_end(i);
    }

  if (i->type != SPKI_TYPE_TAG)
    return 0;

  spki_parse_tag(db, i, &acl->tag);

  if (i->type == SPKI_TYPE_COMMENT)
    spki_parse_skip(i);
      
  if (i->type == SPKI_TYPE_VALID)
    spki_parse_valid(i, acl);

  return spki_parse_end(i);
}

/* The cert must already be initialized. */
enum spki_type
spki_parse_cert(struct spki_acl_db *db, struct spki_iterator *i,
		struct spki_5_tuple *cert)
{
  assert(i->type == SPKI_TYPE_CERT);
  
  spki_parse_type(i);
  
  if (i->type == SPKI_TYPE_VERSION)
    spki_parse_version(i);

  if (i->type == SPKI_TYPE_DISPLAY)
    spki_parse_skip(i);

  if (i->type != SPKI_TYPE_ISSUER)
    return 0;

  if (! (spki_parse_principal(db, i, &cert->issuer)
	 && spki_parse_end(i)))
    return 0;

  if (i->type == SPKI_TYPE_ISSUER_INFO)
    spki_parse_skip(i);    

  if (i->type != SPKI_TYPE_SUBJECT)
    return 0;
  
  /* FIXME: Write an spki_parse_subject function. */
  if (! (spki_parse_principal(db, i, &cert->subject)
	 && spki_parse_end(i)))
    return 0;
  
  if (i->type == SPKI_TYPE_SUBJECT_INFO)
    spki_parse_skip(i);    

  if (i->type == SPKI_TYPE_PROPAGATE)
    {
      cert->flags |= SPKI_PROPAGATE;
      spki_parse_end(i);
    }

  if (i->type != SPKI_TYPE_TAG)
    return 0;
  
  spki_parse_tag(db, i, &cert->tag);
    
  if (i->type == SPKI_TYPE_VALID)
    spki_parse_valid(i, cert);

  if (i->type == SPKI_TYPE_COMMENT)
    spki_parse_skip(i);    

  return spki_parse_end(i);
}
