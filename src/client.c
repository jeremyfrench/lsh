/* client.c
 *
 */

#include <stdio.h>

#include "client.h"
#include "version.h"
#include "session.h"
#include "abstract_io.h"
#include "read_line.h"
#include "read_packet.h"
#include "debug.h"
#include "format.h"
#include "werror.h"
#include "void.c"
#include "xalloc.h"

struct read_handler *make_client_read_line();
struct callback *make_client_close_handler();

static int client_initiate(struct client_callback *closure,
			   int fd)
{
  struct ssh_session *session = ssh_session_alloc();
  struct abstract_write *write =
    io_read_write(closure->backend, fd,
		  make_client_read_line(),
		  closure->block_size,
		  make_client_close_handler());
  
  session->client_version = ssh_format("SSH-" PROTOCOL_VERSION
				     "-" SOFTWARE_VERSION " %lS\r\n",
				     closure->id_comment);
  /* Copies the version string, so that it is isn't freed */
  return A_WRITE(write, ssh_format("%lS", session->client_version));
}

struct client_line_handler
{
  struct line_handler super;
  struct ssh_session *session;
};

static struct read_handler *do_line(struct client_line_handler *closure,
				    UINT32 length,
				    UINT8 *line)
{
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ( ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(line + 4, "1.99-", 5)))
	{
	  struct read_handler *new
	    = make_read_packet(make_debug_processor(make_packet_void(),
						    stderr),
			       closure->session->max_packet);
	  
	  closure->session->server_version
	    = ssh_format("%s", length, line);

	  /* FIXME: Cleanup properly. */
	  free(closure);

	  return new;
	}
      else
	{
	  werror("Unsupported protocol version: ");
	  werror_safe(length, line);
	  werror("\n");
	  /* FIXME: What could be returned here? */
	  fatal("client.c: do_line: Unsupported version.\n");
	  return 0;
	}
    }
  else
    {
      /* Display line */
      werror_safe(length, line);

      /* Read next line */
      return 0;
    }
}

struct read_handler *make_client_read_line(struct ssh_session *s)
{
  struct client_line_handler *closure
    = xalloc(sizeof(struct client_line_handler));
  
  closure->super.handler = (line_handler_f) do_line;
  closure->session = s;
  
  return make_read_line( (struct line_handler *) closure);
}
  
struct fd_callback *make_client_callback(struct io_backend *b,
					 UINT32 block_size)
{
  struct client_callback *connected = xalloc(sizeof(struct client_callback));

  connected->c.f = (fd_callback_f) client_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  
  return (struct fd_callback *) connected;
}
