/* crypto.h
 *
 *
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

#ifndef LSH_CRYPTO_H_INCLUDED
#define LSH_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"

/* Macro to make it easier to loop over several blocks. */
#define FOR_BLOCKS(length, src, dst, blocksize)	\
  assert( !((length) % (blocksize)));           \
  for (; (length); ((length) -= (blocksize),	\
		  (src) += (blocksize),		\
		  (dst) += (blocksize)) )

extern struct crypto_algorithm crypto_arcfour_algorithm;
extern struct crypto_algorithm crypto_des_algorithm;

struct crypto_algorithm *make_twofish_algorithm(UINT32 key_size);
struct crypto_algorithm *make_twofish(void);
struct crypto_algorithm *make_blowfish_algorithm(UINT32 key_size);
struct crypto_algorithm *make_blowfish(void);
struct crypto_algorithm *make_des3(void);

extern struct hash_algorithm sha_algorithm;
extern struct hash_algorithm md5_algorithm;

struct mac_algorithm *make_hmac_algorithm(struct hash_algorithm *h);

#endif
