/* compress.h
 *
 * Interface to compression algorithms...
 * 
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balázs Scheidler, Niels Möller
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

#ifndef LSH_COMPRESS_H_INCLUDED
#define LSH_COMPRESS_H_INCLUDED

#include "lsh.h"

#define GABA_DECLARE
#include "compress.h.x"
#undef GABA_DECLARE

/* GABA:
    (class 
       (name compress_instance)
       (vars
         ;; Output size is limited to the length(outpu) - start -1
	 ;; Returns length of generated output, or zero on error.
         (codec method uint32_t
         	       "struct lsh_string *output" "uint32_t offset"
		       "uint32_t length" "const uint8_t *input")))
*/

#define CODEC(instance, o, s, l, i) \
((instance)->codec((instance), (o), (s), (l), (i)))

#define COMPRESS_DEFLATE 0
#define COMPRESS_INFLATE 1

/* GABA:
   (class
     (name compress_algorithm)
     (vars
        (make_compress method (object compress_instance)
        		"int mode")))
*/

#define MAKE_CODEC(algo, mode) \
((algo)->make_compress((algo), (mode)))

#define MAKE_DEFLATE(algo) MAKE_CODEC((algo), COMPRESS_DEFLATE)
#define MAKE_INFLATE(algo) MAKE_CODEC((algo), COMPRESS_INFLATE)

struct compress_algorithm *make_zlib_algorithm(int level);
struct compress_algorithm *make_zlib(void);

#endif /* LSH_COMPRESS_H_INCLUDED */
