/* void.c
 *
 */

#include "void.h"
#include "xalloc.h"

static int do_ignore(struct void_processor *closure,
		     struct lsh_string *packet)
{
  lsh_string_free(packet);
  return 1;
}

struct packet_processor *make_void_processor()
{
  struct void_processor *closure = xalloc(sizeof(struct void_processor));

  closure->p.f = (abstract_write_f) do_ignore;

  return (struct packet_processor *) closure;
}
