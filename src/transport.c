/* transport.c
 *
 */

#include "transport.h"
#include "xalloc.h"

int apply_processor(struct abstract_write *closure,
		    struct lsh_string *packet)
{
  return closure->f(closure, packet);
}
