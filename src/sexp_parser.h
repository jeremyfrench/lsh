/* sexp_parse.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Ron Rivest, Niels Möller
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

#ifndef LSH_SEXP_PARSER_H_INCLUDED
#define LSH_SEXP_PARSER_H_INCLUDED

#include "parse.h"
#include "sexp.h"

struct sexp *sexp_parse_canonical(struct simple_buffer *buffer);

struct sexp *
string_to_sexp(struct lsh_string *src, int free);

#if 0
struct sexp *sexp_parse_transport(struct simple_buffer *buffer);
struct sexp *sexp_parse_advanced(struct simple_buffer *buffer);
#endif

#endif */ LSH_SEXP_PARSER_H_INCLUDED */
