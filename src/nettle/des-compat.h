/* des-compat.h
 *
 * The des block cipher, libdes/openssl-style interface.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels M�ller
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

#ifndef NETTLE_DES_COMPAT_H_INCLUDED
#define NETTLE_DES_COMPAT_H_INCLUDED

/* According to Assar, des_set_key, des_set_key_odd_parity,
 * des_is_weak_key, plus the encryption functions (des_*_encrypt and
 * des_cbc_cksum) would be a pretty useful subset. */

/* NOTE: This is quite experimental, and not all functions are
 * implemented. Contributions, in particular test cases are welcome. */

#include "des.h"

/* Some names collides with nettle, so we'll need some ugly symbol
 * munging */

#define des_set_key des_key_sched

enum { DES_DECRYPT = 0, DES_ENCRYPT = 1 };

/* Types */
/* NOTE: Typedef:ed arrays should be avoided, but they're used here
 * for compatibility. */

typedef uint32_t DES_LONG;

typedef struct des_ctx des_key_schedule[1];

typedef uint8_t des_cblock[DES_BLOCK_SIZE];

/* Aliases */
#define des_ecb2_encrypt(i,o,k1,k2,e) \
	des_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define des_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	des_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

/* Global flag */
extern int des_check_key;

/* Prototypes */
void
des_ecb3_encrypt(des_cblock *src, des_cblock *dst,
                 des_key_schedule k1, des_key_schedule k2,
                 des_key_schedule k3, int enc);

/* des_cbc_cksum in libdes returns a 32 bit integer, representing the
 * latter half of the output block, using little endian byte order. */
uint32_t
des_cbc_cksum(des_cblock *src, des_cblock *dst,
              long length, des_key_schedule ctx,
              des_cblock *iv);

/* NOTE: Doesn't update iv. */
void
des_cbc_encrypt(des_cblock *src, des_cblock *dst, long length,
		des_key_schedule ctx, des_cblock *iv,
		int enc);

/* Similar, but updates iv. */
void
des_ncbc_encrypt(des_cblock *src, des_cblock *dst, long length,
                 des_key_schedule ctx, des_cblock *iv,
                 int enc);

void
des_ecb_encrypt(des_cblock *src, des_cblock *dst,
		des_key_schedule ctx, int enc);

void
des_ede3_cbc_encrypt(des_cblock *src, des_cblock *dst, long length,
		     des_key_schedule k1,des_key_schedule k2, des_key_schedule k3,
		     des_cblock *iv,
		     int enc);

int
des_set_odd_parity(des_cblock *key);

int
des_key_sched(des_cblock *key, des_key_schedule ctx);

int
des_is_weak_key(des_cblock *key);

#endif /* NETTLE_DES_COMPAT_H_INCLUDED */
