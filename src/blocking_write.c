/* blocking_write.c
 *
 */

#include "blocking_write.h"

#include "xalloc.h"
#include "werror.h"

#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#define CLASS_DEFINE
#include "blocking_write.h.x"
#undef CLASS_DEFINE

static int do_blocking_write(struct abstract_write *w,
			     struct lsh_string *packet)
{
  CAST(blocking_write, closure, w);
  
  UINT32 left = packet->length;
  UINT8 *p = packet->data;

  while(left)
    {
      int written = write(closure->fd, p, left);

      if ( (written < 0)
	   && (errno == EINTR) )
	continue;

      if (written <= 0)
	{
	  werror("blocking_write: writ failed (errno = %d): %s\n",
		 errno, strerror(errno));
	  return LSH_FAIL;
	}

      left -= written;
      p += written;
    }

  lsh_string_free(packet);
  return LSH_OK;
}

struct abstract_write *make_blocking_write(int fd)
{
  NEW(blocking_write, closure);

  closure->super.write = do_blocking_write;
  closure->fd = fd;

  return &closure->super;
}


      
