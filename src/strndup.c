/* strndup.c
 *
 * $Id$
 */

#include "strndup.h"

char * strndup (const char *s, size_t size)
{
  char *r = malloc(size);

  if (size)
    {
      strncpy(r, s, size-1);
      r[size-1] = '\0';
    }
  return r;
}
