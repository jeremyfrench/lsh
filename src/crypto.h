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
