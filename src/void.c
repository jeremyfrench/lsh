/* void.c
 *
 */

#include "void.h"
#include "xalloc.h"
#include "abstract_io.h"

static int do_ignore(struct abstract_write **w,
		     struct lsh_string *packet)
{
  lsh_string_free(packet);
  return 1;
}

struct abstract_write *make_packet_void()
{
  struct abstract_write *closure = xalloc(sizeof(struct abstract_write));

  closure->write = do_ignore;

  return closure;
}
