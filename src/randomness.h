/* randomness.h
 *
 */

#ifndef LSH_RANDOMNESS_H_INCLUDED
#define LSH_RANDOMNESS_H_INCLUDED

#include "lsh_types.h"

struct randomness
{
  void (*random)(struct randomness **closure, UINT32 length, UINT8 *dst);
};

#define RANDOM(r, length, dst) ((r)->random(&(r), length, dst))

#endif /* LSH_RANDOMNESS_H_INCLUDED */
