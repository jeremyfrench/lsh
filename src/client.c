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

/* This limit follows the ssh specification */
#define MAX_LINE 255

/* FIXME: Abstract this out, so that it can be used by the server as
 * well. */
static int do_read_line(struct ... *closure, struct abstract_read *read)
{
  int n = A_READ(read, closure->line, MAX_LINE - closure->pos);
  UINT8 *eol;
  UINT32 length;
  
  if (n<0)
    {
      werror("do_read_1: read() failed, %s\n", strerror(errno));
      return 0;
    }
  closure->pos += n;

  /* Check for eol */
  eol = memchr(closure->buffer, '\n', closure->pos);
  if (!eol)
    {
      if (closure->pos == MAX_LINE)
	{
	  werror("Too long line from server\n");
	  return NULL;
	}
      return closure;
    }
  if ( (eol > closure->buffer)
       && (eol[-1] == '\r'))
    eol--;

  length = eol - closure->buffer;

  if ( (length >= 4) && !memcmp(closure->buffer, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ( ((length >= 8) && !memcmp(closure->buffer + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(closure->buffer +4, "1.99-", 5)))
	{
	  session->recieved_version = ssh_format("%s", length, closure->buffer);

	  /* FIXME: Unget any extra data */
	  /* return a new read-handler */
	  return 0;
	}
      else
	{
	  werror("Unsupported protocol version: ");
	  werror_safe(length, closure->buffer);
	  werror("\n");
	  return 0;
	}
    }
  else
    {
      /* Display line */
      werror_safe(length, closure->buffer);
      memcpy(closure->buffer, closure->buffer + length, length);
      closure->pos = 0;

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
