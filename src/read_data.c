/* read_data.c
 *
 */

#include "read_data.h"

static struct read_handler *do_read_data(struct read_data *closure,
					 struct abstract_read *read)
{
  while(1)
    {
      struct lsh_string packet = lsh_string_alloc(closure->block_size);
      int n = A_READ(read, packet->data, packet->length);
      
      switch(n)
	{
	case 0:
	  lsh_string_free(packet);
	  break;
	case A_FAIL:
	  werror("do_read_data: read() failed, %s\n", strerror(errno));
	  /* Fall through */
	case A_EOF:
	  CALLBACK(closure->close_callback)
	  return 0;
	default:
	  packet->length = n;
	  A_WRITE(closure->handler, packet);
	  break;
	}
    }
}

  
