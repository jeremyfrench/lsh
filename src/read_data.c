/* read_data.c
 *
 */

#include "read_data.h"
#include "werror.h"
#include "xalloc.h"

static int do_read_data(struct read_handler **h,
			struct abstract_read *read)
{
  struct read_data *closure = (struct read_data *) *h;
  
  while(1)
    {
      struct lsh_string *packet = lsh_string_alloc(closure->block_size);
      int n = A_READ(read, packet->data, packet->length);
      
      switch(n)
	{
	case 0:
	  lsh_string_free(packet);
	  break;
	case A_FAIL:
	  /* Fall through */
	case A_EOF:
	  CALLBACK(closure->close_callback);
	  return 0;
	default:
	  packet->length = n;
	  /* FIXME: Use returned value */
	  A_WRITE(closure->handler, packet);
	  break;
	}
    }
}

struct read_handler *make_read_data(struct abstract_write *handler,
				    struct callback *close_callback,
				    UINT32 block_size)
{
  struct read_data *closure = xalloc(sizeof(struct read_data));

  closure->super.handler = do_read_data;
  closure->block_size = block_size;

  closure->handler = handler;
  closure->close_callback = close_callback;

  return &closure->super;
}
