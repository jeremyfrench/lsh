/* packet_dispatch.c
 *
 */

#include "packet_dispatch.h"
#include "xalloc.h"
#include "werror.h"

static int do_dispatch(struct abstract_write **w,
		       struct lsh_string *packet)
{
  struct packet_dispatch *closure = (struct packet_dispatch *) *w;
  
  unsigned start;
  unsigned end;
  unsigned msg;

  if (!packet->length)
    return 0;

  msg = packet->data[0];

  /* Do a binary serch. The number of valid message types should be
   * rather small. */

  start = 0;
  end = closure->table_size;

  while(1)
    {
      unsigned middle = (start + end) / 2;
      unsigned middle_msg = closure->dispatch_table[middle].msg;
      if (middle_msg == msg)
	{
	  /* Found right method */
	  return A_WRITE(closure->dispatch_table[middle].f,
			 packet);
	}
      if (middle == start)
	/* Not found */
	break;
      
      if (middle_msg < msg)
	start = middle;
      else
	end = middle;
    }

  if (closure->other)
    return A_WRITE(closure->other, packet);
  else
    return 0;
}

struct abstract_write *
make_dispatch_processor(unsigned size,
			struct dispatch_assoc *table,
			struct abstract_write *other)
{
  struct packet_dispatch *closure
    = xalloc(sizeof(struct packet_dispatch));
  unsigned i;

  /* Check that message numbers are increasing */
  for(i = 0; i+1 < size; i++)
    if (table[i].msg >= table[i+1].msg)
      fatal("make_dispatch_processor: Table out of order");
  
  closure->super.write = do_dispatch;
  closure->other = other;
  closure->table_size = size;
  closure->dispatch_table = table;

  return &closure->super;
}
