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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_CRYPTO_H_INCLUDED
#define LSH_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"

extern struct crypto_instance crypto_none_instance;
extern struct crypto_algorithm crypto_rc4_algorithm;

extern struct hash_algorithm sha_algorithm;

struct mac_algorithm *make_hmac_algorithm(struct hash_algorithm *h);

struct randomness *make_poor_random(struct hash_algorithm *hash,
				    struct lsh_string *init);

/* Combining block cryptos */

/* Example: To create a tripple DES cbc encryptor:
 *
 * struct crypto_instance des3_cbc
 *  = make_cbc(make_crypto_cascade(3, MAKE_ENCRYPT(&des_algoritm, k1),
 *                                    MAKE_DECRYPT(&des_algoritm, k2),
 *                                    MAKE_ENCRYPT(&des_algoritm, k3)),
 *             CRYPTO_ENCRYPT, iv);
 */

struct crypto_instance *
make_cbc(struct crypto_instance *c, int mode, UINT32 iv);

struct crypto_instance *
make_crypto_cascade(unsigned n, ...);

#endif
