/* abstract_crypto.h
 *
 * Interface to block cryptos and hash functions */

#ifndef LSH_ABSTRACT_CRYPTO_H_INCLUDED
#define LSH_ABSTRACT_CRYPTO_H_INCLUDED

struct crypto_instance
{
  UINT32 block_size;
  /* Length must be a multiple of the block size */
  void (*crypt)(struct crypto_instance *self,
		UINT32 length, UINT8 *dst, UINT8 *src);
};

#define CRYPT(instance, length, src, dst) \
((instance)->crypt((instance), (length), (src), (dst)))
  
struct crypto_algorithm
{
  UINT32 block_size;
  UINT32 key_size;

  struct crypto_instance * (*make_encrypt)(struct crypto_algorithm *self,
					   UINT8 *key);
  struct crypto_instance * (*make_decrypt)(struct crypto_algorithm *self,
					   UINT8 *key);
};

struct hash_instance
{
  UINT32 hash_size;
  void (*update)(struct hash_instance *self,
		 UINT32 length, UINT8 *data);
  void (*digest)(struct hash_instance *self,
		 UINT8 *result);
  struct hash_instance (*copy)(struct hash_instance *self);
};

#define UPDATE(instance, length, data) \
((instance)->update((instance), (length), (data)))

#define DIGEST(instance, result) \
((instance)->digest((instance), (result)))

/* Used for both hash functions ad macs */
#define mac_instance hash_instance
#define mac_size hash_size
  
struct hash_algorithm
{
  UINT32 block_size;
  UINT32 hash_size;
  struct hash_instance (*make_hash)(struct hash_algorithm *self);
};

struct mac_algorithm
{
  UINT32 hash_size;
  UINT32 key_size;
  struct mac_instance (*make_mac)(struct mac_algorithm *self,
				  UINT8 *key);
};


#endif /* LSH_ABSTRACT_CRYPTO_H_INCLUDED */
