/* algorithms.h
 *
 * Translate algorithm identifiers (or names) to algorithm objects.
 *
 * $Id$ */

#ifndef LSH_ALGORITHMS_H_INCLUDED
#define LSH_ALGORITHMS_H_INCLUDED

#include "alist.h"
#include "randomness.h"

#define GABA_DECLARE
#include "algorithms.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name algorithms_options)
     (vars
       (algorithms object alist)

       (crypto_algorithms object int_list)
       (mac_algorithms object int_list)
       (compression_algorithms object int_list)))
*/

struct alist *many_algorithms(unsigned count, ...);
int lookup_crypto(struct alist *algorithms, char *name);
int lookup_mac(struct alist *algorithms, char *name);
int lookup_compression(struct alist *algorithms, char *name);

struct int_list *default_crypto_algorithms(void);
struct int_list *default_mac_algorithms(void);
struct int_list *default_compression_algorithms(void);

void init_algorithms_options(struct algorithms_options *self,
			     struct alist *algorithms);

extern const struct argp algorithms_argp;

#endif */ LSH_ALGORITHMS_H_INCLUDED */
