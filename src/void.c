/* void.c
 *
 */

#include "void.h"
#include "xalloc.h"

static int do_ignore(struct void_processor *closure,
		     struct simple_packet *packet)
{
  free(packet);
  return 1;
}

struct packet_processor *make_void_processor()
{
  struct void_processor *closure = xalloc(sizeof(struct void_processor));

  closure->p.f = (raw_processor_function) do_ignore;

  return (struct packet_processor *) closure;
}
