/* xalloc.c
 *
 */

#include "xalloc.h"
#include "werror.h"

#ifdef DEBUG_ALLOC

void *debug_malloc(size_t size)
{
  static int count = 4711;
  int *res;
  
  /* Count size in ints, and round up */
  size = (size + sizeof(int)-1) / sizeof(int);
  
  res = malloc((size + 3)*sizeof(int));

  if (!res)
    return NULL;
  
  res[0] = count;
  res[1] = size;
  res[size+2] = ~count;
  count++;

  return (void *) (res + 2);
}

void debug_free(void *m)
{
  int *p = (int *) m;
  size_t size = p[-1];

  if (~p[-2] != p[size])
    fatal("Memory currupted!\n");

  free(p-2);
}

#endif

void *xalloc(size_t size)
{
  void *res = lsh_malloc(size);
  if (!res)
    fatal("Virtual memory exhausted");
  return res;
}

struct lsh_string *lsh_string_alloc(UINT32 length)
{
  struct lsh_string *packet
    = xalloc(sizeof(struct lsh_string) - 1 + length);
  packet->length = length;
  return packet;
}

void lsh_string_free(struct lsh_string *packet)
{
  lsh_free(packet);
}
