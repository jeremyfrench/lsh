/* abstract_crypto.h
 *
 * Interface to block cryptos and hash functions */

#ifndef LSH_ABSTRACT_CRYPTO_H_INCLUDED
#define LSH_ABSTRACT_CRYPTO_H_INCLUDED

#include "lsh_types.h"

struct crypto_instance
{
  UINT32 block_size;
  /* Length must be a multiple of the block size */
  void (*crypt)(struct crypto_instance *self,
		UINT32 length, UINT8 *dst, UINT8 *src);
};

#define CRYPT(instance, length, src, dst) \
((instance)->crypt((instance), (length), (src), (dst)))

#define CRYPTO_ENCRYPT 0
#define CRYPTO_DECRYPT 1

struct crypto_algorithm
{
  UINT32 block_size;
  UINT32 key_size;

  struct crypto_instance * (*make_crypt)(struct crypto_algorithm *self,
					 int mode,
					 UINT8 *key);
};

#define MAKE_ENCRYPT(crypto, key) \
((crypto)->make_crypt((crypto), CRYPTO_ENCRYPT, (key)))

#define MAKE_DECRYPT(crypto, key) \
((crypto)->make_crypt((crypto), CRYPTO_DECRYPT, (key)))

struct hash_instance
{
  UINT32 hash_size;
  void (*update)(struct hash_instance *self,
		 UINT32 length, UINT8 *data);
  void (*digest)(struct hash_instance *self,
		 UINT8 *result);
  struct hash_instance * (*copy)(struct hash_instance *self);
};

#define HASH_UPDATE(instance, length, data) \
((instance)->update((instance), (length), (data)))

#define HASH_DIGEST(instance, result) \
((instance)->digest((instance), (result)))

#define HASH_COPY(instance) ((instance)->copy((instance)))

/* Used for both hash functions ad macs */
#define mac_instance hash_instance
#define mac_size hash_size
  
struct hash_algorithm
{
  UINT32 block_size;
  UINT32 hash_size;
  struct hash_instance * (*make_hash)(struct hash_algorithm *self);
};

#define MAKE_HASH(h) ((h)->make_hash((h)))

struct mac_algorithm
{
  UINT32 hash_size;
  UINT32 key_size;
  struct mac_instance * (*make_mac)(struct mac_algorithm *self,
				    UINT8 *key);
};

#define MAKE_MAC(m, key) ((m)->make_mac((m), (key)))

struct signer
{
  /* Returns a signature string, *without* the length field */
  struct lsh_string * (*sign)(struct signer *closure,
			      UINT32 length,
			      UINT8 *data);
};

#define SIGN(signer, length, data) ((signer)->sign((signer), (length), (data)))

struct verifier
{
  int (*verify)(struct verifier *closure,
		UINT32 length,
		UINT8 *data,
		UINT32 signature_length,
		UINT8 * signature_data);
};

#define VERIFY(verifier, length, data, slength, sdata)\
((verifier)->verify((verifier), (length), (data), (slength), (sdata)))
  
struct signature_algorithm
{
  struct signer * (*make_signer)(struct signature_algorithm *closure,
				 UINT32 public_length,
				 UINT8 *public,
				 UINT32 secret_length,
				 UINT8 *secret);
  struct verifier * (*make_verifier)(struct signature_algorithm *closure,
				     UINT32 public_length,
				     UINT8 *public);
};

#endif /* LSH_ABSTRACT_CRYPTO_H_INCLUDED */
