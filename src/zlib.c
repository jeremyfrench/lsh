/* zlib.c
 *
 */

#include "zlib.h"

#define 
static int do_deflate(struct zlib_processor *closure,
		      struct simple_packet *packet)
{
  struct simple_packet *new;

  /* call deflate, copy into new packet */

  new = simple_packet_alloc(...);
  simple_packet_free(packet);
  
  return apply_processor(closure->c->next, new);  
}

struct packet_processor *make_zlib_processor(packet_processor *continuation,
					     int level)
{
  struct debug_processor *closure = xalloc(sizeof(struct zlib_processor));

  closure->c->p->f = (raw_processor_function) do_deflate;
  closure->c->next = continuation;
  /* inititialize closure->zstream */

  return (struct packet_processor *) closure;
}
