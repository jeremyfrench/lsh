/* xalloc.c
 *
 */

#include "xalloc.h"

void *xalloc(size_t size)
{
  void *res = malloc(size);
  if (!res)
    fatal("Virtual memory exhausted");
  return res;
}
