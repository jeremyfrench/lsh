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

#ifndef LSH_READ_SCAN_H_INCLUDED
#define LSH_READ_SCAN_H_INCLUDED

#include "abstract_io.h"

#define CLASS_DECLARE
#include "read_scan.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name scanner)
     (vars
       ;; Returns some combination of LSH_OK, LSH_FAIL and LSH_CLOSE.
       (scan indirect-method int int)))
*/

#define TOKEN_EOF -1
#define TOKEN_EOS -2
#define TOKEN_ERROR -3
#define TOKEN_NONE -4

#define SCAN(s, t) ((s)->scan(&(s), (t)))

struct read_handler *make_read_scan(size_t buffer_size, struct scanner *scanner);

#endif /* LSH_READ_SCAN_H_INCLUDED */
