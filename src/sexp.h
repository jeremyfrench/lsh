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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_SEXP_H_INCLUDED
#define LSH_SEXP_H_INCLUDED

#include "bignum.h"
#include "command.h"
#include "list.h"
#include "lsh_argp.h"

#include "sexp_table.h"

/* Forward declaration */
struct sexp_iterator;

#define GABA_DECLARE
#include "sexp.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name sexp)
     (vars
       ;; NULL for non-lists
       (iter method "struct sexp_iterator *")
       (format method "struct lsh_string *" "int style" "unsigned indent")))
*/

#define SEXP_FORMAT(e, s, i) ((e)->format((e), (s), (i)))
#define SEXP_ITER(e) ((e)->iter((e)))

/* GABA:
   (class
     (name sexp_cons)
     (super sexp)
     (vars
       (car object sexp)
       (cdr object sexp_cons)))
*/

/* ;; GABA:
   (class
     (name sexp_atom)
     (super sexp)
     (vars
       (atom . int)))
*/


/* Iterator abstraction idea taken from Ron's code */
/* GABA:
   (class
     (name sexp_iterator)
     (vars
       (get method "struct sexp *")
       (set method void "struct sexp *")
       (next method void)))
*/

#define SEXP_GET(i) ((i)->get((i)))
#define SEXP_SET(i, v) ((i)->set((i), (v)))
#define SEXP_NEXT(i) ((i)->next((i)))

/* Syntax styles */

#define SEXP_CANONICAL 0
#define SEXP_TRANSPORT 1
#define SEXP_ADVANCED 2

/* Like advanced, but allow international characters in quoted strings. */
#define SEXP_INTERNATIONAL 3

struct lsh_string *sexp_format(struct sexp *e, int style, unsigned indent);

struct lsh_string *encode_base64(struct lsh_string *s,
				 const char *delimiters,
				 unsigned indent, int free);

/* Creating sexps */

/* Consumes its args (display may be NULL) */
struct sexp *make_sexp_string(struct lsh_string *d, struct lsh_string *c);

/* atom->sexp */
struct sexp *sexp_a(const int a);

/* cstring->sexp */
struct sexp *sexp_z(const char *s);

/* mpz->atom */
struct sexp *sexp_un(const mpz_t n);
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

/* Checks that the sexp is a simple string (i.e. no display part).
 * e == NULL is allowed. */
struct lsh_string *sexp2string(struct sexp *e);

/* Returns an ATOM_FOO constant if e is a simple sexp string
 * corresponding to an atom. Or zero if that is not the case. */
UINT32 sexp2atom(struct sexp *e);

/* int sexp_null_cdr(struct sexp *e); */

struct lsh_string *sexp_contents(const struct sexp *e);
struct lsh_string *sexp_display(const struct sexp *e);
int sexp_atom(const struct sexp *e);
int sexp_bignum_u(const struct sexp *e, mpz_t n);
int sexp_bignum_s(const struct sexp *e, mpz_t n);

/* Utility functions for parsing spki objects. */

/* FIXME: These function might get obsoleted by spki.c */

int sexp_eqz(const struct sexp *e, const char *s);
int sexp_check_type(struct sexp *e, const char *type,
		    struct sexp_iterator **res);
struct sexp *sexp_assz(struct sexp_iterator *i, const char *name);
int sexp_get_un(struct sexp_iterator *i, const char *name, mpz_t n);

extern int sexp_char_classes[];

/* Parsing sexp */

/* GABA:
   (class
     (name sexp_handler)
     (vars
       ;; Called when a complete sexpression has been read.
       (handler method int "struct sexp *e")))
*/

#define HANDLE_SEXP(h, s) ((h)->handler((h), (s)))

struct read_handler *
make_read_sexp(int style, int goon,
	       struct command_continuation *c,
	       struct exception_handler *e);

extern const struct argp sexp_argp;
#define sexp_argp_input int

#endif /* LSH_SEXP_H_INCLUDED */

 
