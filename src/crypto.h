/* crypto.h
 *
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

#endif
