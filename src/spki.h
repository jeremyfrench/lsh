/* spki.h
 *
 * An implementation of SPKI certificate checking
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balazs Scheidler
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

#ifndef LSH_SPKI_H_INCLUDED
#define LSH_SPKI_H_INCLUDED

#include "exception.h"
#include "sexp.h"
#include "alist.h"

#define GABA_DECLARE
#include "spki.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name spki_exception)
     (super exception)
     (vars
       (expr object sexp)))
*/

struct exception *
make_spki_exception(UINT32 type, const char *msg, struct sexp *expr);

UINT32 spki_get_type(struct sexp *e, struct sexp_iterator **res);

int spki_check_type(struct sexp *e, UINT32 type, struct sexp_iterator **res);

/* FIXME: should support keyblobs other than ssh-dss */
struct sexp *keyblob2spki(struct lsh_string *keyblob);

extern struct command spki_public2private;
#define PRIVATE2PUBLIC (&spki_public2private.super)

#if 0
extern struct spki_hash spki_hash_md5;
#define SPKI_HASH_MD5 (&spki_hash_md5.super.super)
extern struct spki_hash spki_hash_sha1;
#define SPKI_HASH_SHA1 (&spki_hash_sha1.super.super)
#endif

struct command *
make_spki_hash(int name, struct hash_algorithm *algorithm);

struct command *
make_spki_parse_key(struct randomness *random);

struct keypair *
read_spki_key_file(const char *name,
		   struct randomness *r,
		   struct exception_handler *e);


#endif /* LSH_SPKI_H_INCLUDED */
