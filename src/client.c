/* client.c
 *
 */

#include "client.h"
#include "version.h"

static int client_initiate(struct client_callback *closure,
		    int fd)
{
  struct abstract_write *write = io_write(closure->backend, fd, closure->block_size,
					  ...close);

  struct session = session_alloc(...);
  session->sent_version = ssh_format("SSH-" PROTOCOL_VERSION
				     "-" SOFTWARE_VERSION " %lS\r\n",
				     closure->id_comment);
  /* FIXME: Retain the version string (by copying or increfing) */
#error foo
  A_WRITE(write, session->sent_version);
  io_read(closure->backend, fd, make_client_read_line());
}

struct client_line_handler
{
  struct line_handler super;
  struct session *session;
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
	  closure->session->recieved_version
	    = ssh_format("%s", length, line);

	  /* return a new read-handler */
	  return ...
	}
      else
	{
	  werror("Unsupported protocol version: ");
	  werror_safe(length, line);
	  werror("\n");
	  return 0;
	}
    }
  else
    {
      /* Display line */
      werror_safe(length, line);

      /* Read next line */
      return closure;
    }
}

struct fd_callback *make_client_callback(struct io_backend *b,
					 UINT32 block_size)
{
  struct client_callback connected = xalloc(sizeof(struct client_callback));

  connected->c.f = (fd_callback_f) client_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  
  return (struct fd_callback *) connected;
}
