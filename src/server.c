/* server.c
 *
 */

#include "server.h"

#include "version.h"
#include "connection.h"
#include "abstract_io.h"
#include "read_line.h"
#include "read_packet.h"
#include "debug.h"
#include "format.h"
#include "werror.h"
#include "void.h"
#include "xalloc.h"

struct read_handler *make_server_read_line();
struct callback *make_server_close_handler();

static int server_initiate(struct server_callback *closure,
			   int fd)
{
  struct ssh_connection *connection = ssh_connection_alloc();
  struct abstract_write *write =
    io_read_write(closure->backend, fd,
		  make_server_read_line(),
		  closure->block_size,
		  make_server_close_handler());
  
  connection->server_version
    = ssh_format("SSH-%z-%z %z\r\n",
		 PROTOCOL_VERSION,
		 SOFTWARE_SERVER_VERSION,
		 closure->id_comment);
  /* Copies the version string, so that it is isn't freed */
  return A_WRITE(write, ssh_format("%lS", connection->server_version));
}

struct server_line_handler
{
  struct line_handler super;
  struct ssh_connection *connection;
};

static struct read_handler *do_line(struct server_line_handler *closure,
				    UINT32 length,
				    UINT8 *line)
{
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	{
	  struct read_handler *new
	    = make_read_packet(make_debug_processor(make_packet_void(),
						    stderr),
			       closure->connection->max_packet);
	  
	  closure->connection->client_version
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

	  fatal("server.c: do_line: Unsupported version.\n"); 
	  /* FIXME: What could be returned here? */
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
