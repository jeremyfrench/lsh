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

#define CLASS_DECLARE
#include "abstract_crypto.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name crypto_instance)
     (vars
       (block_size simple UINT32)
       ; Length must be a multiple of the block size        
       (crypt method void
              "UINT32 length" "UINT8 *src" "UINT8 *dst")))
*/
#if 0
struct crypto_instance
{
  struct lsh_object header;
  UINT32 block_size;
  /* Length must be a multiple of the block size */
  void (*crypt)(struct crypto_instance *self,
		UINT32 length, UINT8 *src, UINT8 *dst);
};
#endif

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
       (make_crypt method (object crypto_instance)
                   "int mode" "UIINT8 *key")))
*/
     
#if 0
struct crypto_algorithm
{
  struct lsh_object header;
  UINT32 block_size;
  UINT32 key_size;

  struct crypto_instance * (*make_crypt)(struct crypto_algorithm *self,
					 int mode,
					 UINT8 *key);
};
#endif

#define MAKE_ENCRYPT(crypto, key) \
((crypto)->make_crypt((crypto), CRYPTO_ENCRYPT, (key)))

#define MAKE_DECRYPT(crypto, key) \
((crypto)->make_crypt((crypto), CRYPTO_DECRYPT, (key)))

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

#if 0     
struct hash_instance
{
  struct lsh_object header;

  UINT32 hash_size;
  void (*update)(struct hash_instance *self,
		 UINT32 length, UINT8 *data);
  void (*digest)(struct hash_instance *self,
		 UINT8 *result);
  struct hash_instance * (*copy)(struct hash_instance *self);
};
#endif

#define HASH_UPDATE(instance, length, data) \
((instance)->update((instance), (length), (data)))

#define HASH_DIGEST(instance, result) \
((instance)->digest((instance), (result)))

#define HASH_COPY(instance) ((instance)->copy((instance)))

/* Used for both hash functions ad macs */
#define mac_instance hash_instance
#define mac_size hash_size

/* CLASS:
   (class
     (name hash_algorithm)
     (vars
       (block_size simple UINT32)
       (hash_size simple UINT32)
       (make_hash method (object hash_instance))))
*/

#if 0
struct hash_algorithm
{
  struct lsh_object header;
  UINT32 block_size;
  UINT32 hash_size;
  struct hash_instance * (*make_hash)(struct hash_algorithm *self);
};
#endif

#define MAKE_HASH(h) ((h)->make_hash((h)))

/* CLASS:
   (class
     (name mac_algorithm)
     (vars
       (hash_size simple UINT32)
       (key_size simple UINT32)
       (make_mac method (object mac_instance) "UINT8 *key")))
*/

#if 0
struct mac_algorithm
{
  struct lsh_object header;
  UINT32 hash_size;
  UINT32 key_size;
  struct mac_instance * (*make_mac)(struct mac_algorithm *self,
				    UINT8 *key);
};
#endif
#define MAKE_MAC(m, key) ((m)->make_mac((m), (key)))

/* CLASS:
   (class
    (name signer)
    (vars
      ; Returns a signature string, *without* the length field
      (sign method (string)
            "UINT32 length" "UINT8 *data")))
*/

#if 0
struct signer
{
  struct lsh_object header;
  /* Returns a signature string, *without* the length field */
  struct lsh_string * (*sign)(struct signer *closure,
			      UINT32 length,
			      UINT8 *data);
};
#endif
#define SIGN(signer, length, data) ((signer)->sign((signer), (length), (data)))

/* CLASS:
   (class
     (name verifier)
     (vars
       (verify method int
       	       "UINT32 length" "UINT8 *data"
	       "UINT32 signature_length" "UINT8 * signature_data")))
*/

#if 0
struct verifier
{
  struct lsh_object header;
  int (*verify)(struct verifier *closure,
		UINT32 length,
		UINT8 *data,
		UINT32 signature_length,
		UINT8 * signature_data);
};
#endif

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

#if 0
struct signature_algorithm
{
  struct lsh_object header;
  struct signer * (*make_signer)(struct signature_algorithm *closure,
				 UINT32 public_length,
				 UINT8 *public,
				 UINT32 secret_length,
				 UINT8 *secret);
  struct verifier * (*make_verifier)(struct signature_algorithm *closure,
				     UINT32 public_length,
				     UINT8 *public);
};
#endif

#define MAKE_SIGNER(a, pl, p, sl, s) \
((a)->make_signer((a), (pl), (p), (sl), (s)))

#define MAKE_VERIFIER(a, pl, p) \
((a)->make_verifier((a), (pl), (p)))

#endif /* LSH_ABSTRACT_CRYPTO_H_INCLUDED */
