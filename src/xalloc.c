/* xalloc.c
 *
 */

#include "xalloc.h"
#include "werror.h"

void *xalloc(size_t size)
{
  void *res = malloc(size);
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
  free(packet);
}
