/* server.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

static int server_initiate(struct fd_callback **c,
			   int fd)
{
  struct server_callback *closure = (struct server_callback *) *c;
  
  /* FIXME: Should pass a key exchange handler, not NULL! */
  struct ssh_connection *connection = make_ssh_connection(NULL);
  struct abstract_write *write =
    io_read_write(closure->backend, fd,
		  make_server_read_line(),
		  closure->block_size,
		  make_server_close_handler());
  
  connection->server_version
    = ssh_format("SSH-%lz-%lz %lz",
		 PROTOCOL_VERSION,
		 SOFTWARE_SERVER_VERSION,
		 closure->id_comment);

  return A_WRITE(write, ssh_format("%lS\r\n", connection->server_version));
}

struct server_line_handler
{
  struct line_handler super;
  struct ssh_connection *connection;
};

static struct read_handler *do_line(struct line_handler **h,
				    UINT32 length,
				    UINT8 *line)
{
  struct server_line_handler *closure = (struct server_line_handler *) *h;
  
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	{
	  struct read_handler *new
	    = make_read_packet(make_packet_debug(&closure->connection->super,
						 stderr),
			       closure->connection->max_packet);
	  
	  closure->connection->client_version
	    = ssh_format("%ls", length, line);

	  verbose("Client version: ");
	  verbose_safe(closure->connection->client_version->length,
		       closure->connection->client_version->data);
	  verbose("\n");
	  
	  /* FIXME: Cleanup properly. */
	  lsh_free(closure);

	  return new;
	}
      else
	{
	  werror("Unsupported protocol version: ");
	  werror_safe(length, line);
	  werror("\n");

	  /* FIXME: Clean up properly */
	  lsh_free(closure);
	  *h = 0;
		  
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

struct read_handler *make_server_read_line(struct ssh_connection *s)
{
  struct server_line_handler *closure
    = xalloc(sizeof(struct server_line_handler));
  
  closure->super.handler = do_line;
  closure->connection = s;
  
  return make_read_line(&closure->super);
}

struct fd_callback *make_server_callback(struct io_backend *b,
					 char *comment,
					 UINT32 block_size)
					 
{
  struct server_callback *connected = xalloc(sizeof(struct server_callback));

  connected->super.f = server_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  connected->id_comment = comment;
  
  return &connected->super;
}

static int server_die(struct callback *closure)
{
  werror("Connection died.\n");
  /* FIXME: Cleanup properly. */
  return 0;  /* Ignored */
}

struct callback *make_server_close_handler()
{
  struct callback *c = xalloc(sizeof(struct callback));

  c->f = server_die;

  return c;
}

