/* blocking_write.c
 *
 */

#include "blocking_write.h"

#include "io.h"
#include "xalloc.h"

/* CLASS:
   (class
     (name blocking_write)
     (super abstract_write)
     (vars
       (fd . int)
       (write . (pointer (function int int UINT32 "UINT8 *")))))
*/

#include "blocking_write.c.x"

static int do_blocking_write(struct abstract_write *w,
			     struct lsh_string *packet)
{
  CAST(blocking_write, closure, w);
  int success = closure->write(closure->fd, packet->length, packet->data);

  lsh_string_free(packet);

  return success ? LSH_OK : LSH_FAIL | LSH_DIE; 
}

struct abstract_write *make_blocking_write(int fd, int with_nonblocking)
{
  NEW(blocking_write, closure);

  closure->super.write = do_blocking_write;
  closure->write = (with_nonblocking ? write_raw_with_poll : write_raw);
  closure->fd = fd;

  return &closure->super;
}
