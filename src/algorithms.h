/* algorithms.c
 *
 * Translate algorithm identifiers (or names) to algorithm objects.
 *
 * $Id$ */

#ifndef LSH_ALGORITHMS_H_INCLUDED
#define LSH_ALGORITHMS_H_INCLUDED

#include "alist.h"
#include "randomness.h"

struct alist *many_algorithms(unsigned count, ...);
int lookup_crypto(struct alist *algorithms, char *name);
int lookup_mac(struct alist *algorithms, char *name);
int lookup_compression(struct alist *algorithms, char *name);

struct int_list *default_crypto_algorithms(void);
struct int_list *default_mac_algorithms(void);
struct int_list *default_compression_algorithms(void);

#endif */ LSH_ALGORITHMS_H_INCLUDED */
