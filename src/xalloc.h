/* xalloc.h
 *
 */

#ifndef LSH_XALLOC_H_INCLUDED
#define LSH_XALLOC_H_INCLUDED

#include <stdlib.h>
#include "lsh_types.h"

void *xalloc(size_t size);

/* Allocation */

/* The memory allocation model (for strings) is as follows:
 *
 * Packets are allocated when the are needed. A packet may be passed
 * through a chain of processing functions, until it is finally
 * discarded or transmitted, at which time it is deallocated.
 * Processing functions may deallocate their input packets and
 * allocate fresh packets to pass on; therefore, any data from a
 * packet that is needed later must be copied into some other storage.
 *
 * At any time, each packet is own by a a particular processing
 * function. Pointers into a packet are valid only while you own it.
 * */

struct lsh_string *lsh_string_alloc(UINT32 size);
void lsh_string_free(struct lsh_string *packet);

#ifdef DEBUG_ALLOC
void *debug_malloc(size_t size);
void debug_free(void *m);
  
#define lsh_free debug_free
#define lsh_malloc debug_malloc
#else
#define lsh_free free
#define lsh_malloc malloc
#endif

#endif /* LSH_XALLOC_H_INCLUDED */
