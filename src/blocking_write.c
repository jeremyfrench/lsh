/* blocking_write.c
 *
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static int do_write(struct pad_processor *closure,
		    struct simple_packet *packet)
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

  simple_packet_free(packet);
  return 1;
}

struct packet_processor *make_blocking_write_procesor(int fd)
{
  struct blocking_write_processor *closure
    = xalloc(sizeof(struct blocking_write_processor_processor));

  closure->p->f = (raw_processor_function) do_write;
  closure->fd = fd;

  return (struct packet_processor *) closure;
}

      
