/* blocking_write.c
 *
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static int do_write(struct pad_processor *closure,
		    struct lsh_string *packet)
{
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
  struct blocking_write_processor *closure
    = xalloc(sizeof(struct blocking_write_processor_processor));

  closure->p->f = (abstract_write_f) do_write;
  closure->fd = fd;

  return (struct abstract_write *) closure;
}

      
