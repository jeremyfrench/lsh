/* zlib.c
 *
 */

#include "zlib.h"

#define 
static int do_deflate(struct zlib_processor *closure,
		      struct lsh_string *packet)
{
  struct lsh_string *new;

  /* call deflate, copy into new packet */

  new = lsh_string_alloc(...);
  lsh_string_free(packet);
  
  return apply_processor(closure->c->next, new);  
}

struct abstract_write *make_packet_zlib(abstract_write *continuation,
					int level)
{
  struct debug_processor *closure = xalloc(sizeof(struct zlib_processor));

  closure->c->p->f = (abstract_write_f) do_deflate;
  closure->c->next = continuation;
  /* inititialize closure->zstream */

  return (struct abstract_write *) closure;
}
