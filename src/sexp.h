/* sexp.h
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

#ifndef LSH_SEXP_H_INCLUDED
#define LSH_SEXP_H_INCLUDED

#include "bignum.h"
#include "list.h"

#include "sexp_table.h"

/* Forward declaration */
struct sexp_iterator;

#define CLASS_DECLARE
#include "sexp.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name sexp)
     (vars
       ;; NULL for non-lists
       (iter method "struct sexp_iterator *")
       (format method "struct lsh_string *" "int style")))
*/

#define SEXP_FORMAT(e, s) ((e)->format((e), (s)))

/* CLASS:
   (class
     (name sexp_cons)
     (super sexp)
     (vars
       (car object sexp)
       (cdr object sexp_cons)))
*/

/* ;; CLASS:
   (class
     (name sexp_atom)
     (super sexp)
     (vars
       (atom . int)))
*/


/* Iterator abstraction idea taken from Ron's code */
/* CLASS:
   (class
     (name sexp_iterator)
     (vars
       (get method "struct sexp *")
       (set method void "struct sexp *")
       (next method void)))
*/

#define SEXP_CURRENT(i) ((i)->current((i)))
#define SEXP_NEXT(i) ((i)->next((i)))

/* Output styles */

#define SEXP_CANONICAL 0
#define SEXP_TRANSPORT 1
#define SEXP_ADVANCED 2

/* Like advanced, but allow international characters in quoted strings. */
#define SEXP_INTERNATIONAL 3

struct lsh_string *sexp_format(struct sexp *e, int style);

struct lsh_string *encode_base64(struct lsh_string *s,
				 const char *delimiters,
				 int free);

/* Creating sexps */

/* Consumes its args (display may be NULL) */
struct sexp *make_sexp_string(struct lsh_string *d, struct lsh_string *c);

/* atom->sexp */
struct sexp *sexp_a(const int a);

/* cstring->sexp */
struct sexp *sexp_z(const char *s);

/* mpz->atom */
struct sexp *sexp_n(const mpz_t n);
struct sexp *sexp_sn(const mpz_t n);

/* cons */
struct sexp *sexp_c(struct sexp *car, struct sexp_cons *cdr);

/* list */
struct sexp *sexp_l(unsigned n, ...);

/* vector */
struct sexp *sexp_v(struct object_list *l);

#if 0
/* Extracting information from sexp. These functions accept NULL
 * arguments, and return NULL if the conversion is not possible */

int sexp_consp(struct sexp *e);

/* For lists */
struct sexp *sexp_car(const struct sexp *e);
struct sexp *sexp_cdr(const struct sexp *e);
#endif

int sexp_nullp(const struct sexp *e);
int sexp_atomp(const struct sexp *e);

/* int sexp_null_cdr(struct sexp *e); */

struct lsh_string *sexp_contents(const struct sexp *e);
struct lsh_string *sexp_display(const struct sexp *e);
int sexp_atom(const struct sexp *e);
int sexp_bignum_u(const struct sexp *e, mpz_t n);
int sexp_bignum_s(const struct sexp *e, mpz_t n);

extern int sexp_char_classes[];

/* Parsing sexp */

/* CLASS:
   (class
     (name sexp_handler)
     (vars
       ;; Called when a complete sexpression has been read.
       (handler method int "struct sexp *e")))
*/

#define HANDLE_SEXP(h, s) ((h)->handler((h), (s)))
     
#endif /* LSH_SEXP_H_INCLUDED */

 
