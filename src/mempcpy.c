/* mempcpy.c
 *
 */

#include "mempcpy.h"

void *mempcpy (void *to, const void *from, size_t size)
{
  memcpy(to, from, size);
  return (char *) to + size;
}
