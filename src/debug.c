/* debug.c
 *
 */

#include "debug.h"
#include "xalloc.h"

static int do_debug(struct abstract_write **w,
		    struct lsh_string *packet)
{
  struct packet_debug *closure
    = (struct packet_debug *) *w;
  
  UINT32 i;
  
  fprintf(closure->output, "DEBUG: (packet size %d = 0x%x)\n",
	  packet->length, packet->length);

  for(i=0; i<packet->length; i++)
  {
    if (! i%16)
      fprintf(closure->output, "\n%08x: ", i);
    
    fprintf(closure->output, "%02x ", packet->data[i]);
  }

  fprintf(closure->output, "\n");

  return A_WRITE(closure->super.next, packet);
}

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, FILE *output)
{
  struct packet_debug *closure = xalloc(sizeof(struct packet_debug));

  closure->super.super.write = do_debug;
  closure->super.next = continuation;
  closure->output = output;

  return &closure->super.super;
}


