/* read_scan.h
 *
 * Buffered reader, which passes characters one at a time to a
 * scanner.
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

#error read_scan.h is obsolete

#ifndef LSH_READ_SCAN_H_INCLUDED
#define LSH_READ_SCAN_H_INCLUDED

#include "abstract_io.h"

#define GABA_DECLARE
#include "read_scan.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name scanner)
     (vars
       ;; Returns some combination of LSH_OK, LSH_FAIL and LSH_CLOSE.
       (scan indirect-method int int)))
*/

/* Temporary hack to get it to compile */
#define LSH_OK 0
#define LSH_FAIL 1
#define LSH_CLOSE 2
#define LSH_SYNTAX 4
#define LSH_DIE 8

#define TOKEN_EOF -1
#define TOKEN_EOS -2
#define TOKEN_ERROR -3
#define TOKEN_NONE -4

#define SCAN(s, t) ((s)->scan(&(s), (t)))

struct read_handler *make_read_scan(struct scanner *scanner);

#endif /* LSH_READ_SCAN_H_INCLUDED */
