/* abstract_crypto.h
 *
 * Interface to block cryptos and hash functions
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

#ifndef LSH_ABSTRACT_CRYPTO_H_INCLUDED
#define LSH_ABSTRACT_CRYPTO_H_INCLUDED

#include "lsh_types.h"

#include "list.h"

/* Use the same instance struct for both hash functions and macs. This
 * is a little ugly. */
#define mac_instance_class hash_instance_class
#define mac_instance hash_instance
#define mac_size hash_size

#define CLASS_DECLARE
#include "abstract_crypto.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name crypto_instance)
     (vars
       (block_size simple UINT32)
       ; Length must be a multiple of the block size.
       ; NOTE: src == dst is allowed.
       (crypt method void
              "UINT32 length" "const UINT8 *src" "UINT8 *dst")))
*/

#define CRYPT(instance, length, src, dst) \
((instance)->crypt((instance), (length), (src), (dst)))

#define CRYPTO_ENCRYPT 0
#define CRYPTO_DECRYPT 1

/* CLASS:
   (class
     (name crypto_algorithm)
     (vars
       (block_size simple UINT32)
       (key_size simple UINT32)
       (iv_size simple UINT32)
       (make_crypt method (object crypto_instance)
                   "int mode" "const UINT8 *key" "const UINT8 *iv")))
*/

#define MAKE_CRYPT(crypto, mode, key, iv) \
((crypto)->make_crypt((crypto), (mode), (key), (iv)))     

#define MAKE_ENCRYPT(crypto, key, iv) \
     MAKE_CRYPT((crypto), CRYPTO_ENCRYPT, (key), (iv))

#define MAKE_DECRYPT(crypto, key, iv) \
     MAKE_CRYPT((crypto), CRYPTO_DECRYPT, (key), (iv))
     
/* FIXME: Hashes could use non-virtual methods. */
     
/* CLASS:
   (class
     (name hash_instance)
     (vars
       (hash_size simple UINT32)
       (update method void 
	       "UINT32 length" "UINT8 *data")
       (digest method void "UINT8 *result")
       (copy method (object hash_instance))))
*/

#define HASH_UPDATE(instance, length, data) \
((instance)->update((instance), (length), (data)))

#define HASH_DIGEST(instance, result) \
((instance)->digest((instance), (result)))

#define HASH_COPY(instance) ((instance)->copy((instance)))

/* CLASS:
   (class
     (name hash_algorithm)
     (vars
       (block_size simple UINT32)
       (hash_size simple UINT32)
       (make_hash method (object hash_instance))))
*/

#define MAKE_HASH(h) ((h)->make_hash((h)))

/* CLASS:
   (class
     (name mac_algorithm)
     (vars
       (hash_size simple UINT32)
       (key_size simple UINT32)
       (make_mac method (object mac_instance) "const UINT8 *key")))
*/

#define MAKE_MAC(m, key) ((m)->make_mac((m), (key)))

/* CLASS:
   (class
    (name signer)
    (vars
      ; Returns a signature string, *without* the length field
      (sign method (string)
            "UINT32 length" "UINT8 *data")))
*/

#define SIGN(signer, length, data) ((signer)->sign((signer), (length), (data)))

/* CLASS:
   (class
     (name verifier)
     (vars
       (verify method int
       	       "UINT32 length" "UINT8 *data"
	       "UINT32 signature_length" "UINT8 * signature_data")))
*/

#define VERIFY(verifier, length, data, slength, sdata)\
((verifier)->verify((verifier), (length), (data), (slength), (sdata)))

/* CLASS:
   (class
     (name signature_algorithm)
     (vars
       (make_signer method (object signer)
                    "UINT32 public_length" "UINT8 *public"
		    "UINT32 secret_length" "UINT8 *secret")
		    
       (make_verifier method (object verifier)
                    "UINT32 public_length" "UINT8 *public")))
*/

#define MAKE_SIGNER(a, pl, p, sl, s) \
((a)->make_signer((a), (pl), (p), (sl), (s)))

#define MAKE_VERIFIER(a, pl, p) \
((a)->make_verifier((a), (pl), (p)))

/* Combining block cryptos */

/* Example: To create a tripple DES cbc encryptor:
 *
 * struct crypto_algorithm des3_cbc
 *  = make_cbc(crypto_cascade(3, des_algorithm,
 *                               crypto_invert(des_algorithm)
 *                               des_algorithm, -1));
 */

struct crypto_algorithm *crypto_cbc(struct crypto_algorithm *inner);
struct crypto_algorithm *crypto_invert(struct crypto_algorithm *inner);
struct crypto_algorithm *crypto_cascadel(struct object_list *cascade);
struct crypto_algorithm *crypto_cascade(unsigned n, ...);

/* Utility functions */
void memxor(UINT8 *dst, const UINT8 *src, size_t n);
UINT32 gcd(UINT32 x, UINT32 y);
UINT32 lcm(UINT32 x, UINT32 y);

#endif /* LSH_ABSTRACT_CRYPTO_H_INCLUDED */
