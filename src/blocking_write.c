/* blocking_write.c
 *
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#warning blocking_write.c is obsolete

static int do_write(struct abstract_write *w,
		    struct lsh_string *packet)
{
  CAST(packet_blocking_write, closure, w);
  
  UINT32 left = packet->length;
  UINT8 *p = packet->data;

  while(left)
    {
      int written = write(closure->fd, p, left);

      if ( (written < 0)
	   && (errno == EINTR) )
	continue;

      if (written <= 0)
	return 0;

      left -= written;
      p += written;
    }

  lsh_string_free(packet);
  return 1;
}

struct abstract_write *make_blocking_write_procesor(int fd)
{
  struct blocking_write_processor *closure;

  NEW(closure);

  closure->p->f = do_write;
  closure->fd = fd;

  return &closure->super;
}

      
