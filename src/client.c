/* client.c
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

#include <stdio.h>

#include "client.h"

#include "abstract_io.h"
#include "connection.h"
#include "crypto.h"
#include "debug.h"
#include "encrypt.h"
#include "format.h"
#include "pad.h"
#include "read_line.h"
#include "read_packet.h"
#include "unpad.h"
#include "version.h"
#include "void.h"
#include "werror.h"
#include "xalloc.h"

struct read_handler *make_client_read_line();
struct callback *make_client_close_handler();

static int client_initiate(struct fd_callback **c,
			   int fd)
{
  struct client_callback *closure
    = (struct client_callback *) *c;

  /* FIXME: Should pass a key exchange handler, not NULL! */
  struct ssh_connection *connection
    = make_ssh_connection(NULL);

  connection_init_io(connection,
		     io_read_write(closure->backend, fd,
				   make_client_read_line(connection),
				   closure->block_size,
				   make_client_close_handler()),
		     closure->random);
  
  connection->client_version
    = ssh_format("SSH-%lz-%lz %lz",
		 PROTOCOL_VERSION,
		 SOFTWARE_CLIENT_VERSION,
		 closure->id_comment);
  
  return A_WRITE(connection->raw,
		 ssh_format("%lS\r\n", connection->client_version));
}

struct client_line_handler
{
  struct line_handler super;
  struct ssh_connection *connection;
};

static struct read_handler *do_line(struct line_handler **h,
				    UINT32 length,
				    UINT8 *line)
{
  struct client_line_handler *closure
    = (struct client_line_handler *) *h;
  
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ( ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(line + 4, "1.99-", 5)))
	{
	  struct read_handler *new = make_read_packet
	    (make_packet_debug
	     (make_packet_unpad(&closure->connection->super),
	      stderr),
	     closure->connection);
	  
	  closure->connection->server_version
	    = ssh_format("%ls", length, line);

	  verbose("Client version: ");
	  verbose_safe(closure->connection->client_version->length,
		       closure->connection->client_version->data);
	  verbose("\nServer version: ");
	  verbose_safe(closure->connection->server_version->length,
		       closure->connection->server_version->data);
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
	  *h = NULL;
		  
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

struct read_handler *make_client_read_line(struct ssh_connection *c)
{
  struct client_line_handler *closure
    = xalloc(sizeof(struct client_line_handler));
  
  closure->super.handler = do_line;
  closure->connection = c;
  
  return make_read_line(&closure->super);
}
  
struct fd_callback *make_client_callback(struct io_backend *b,
					 char *comment,
					 UINT32 block_size,
					 struct randomness *r)
					 
{
  struct client_callback *connected = xalloc(sizeof(struct client_callback));

  connected->super.f = client_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  connected->id_comment = comment;
  connected->random = r;
  return &connected->super;
}

static int client_die(struct callback *closure)
{
  werror("Connection died.\n");
  exit(1);
}

struct callback *make_client_close_handler()
{
  struct callback *c = xalloc(sizeof(struct callback));

  c->f = client_die;

  return c;
}

#if 0
/* FIXME: HERE */
struct abstract_write *make_client_dispatch(struct ssh_connection *c)
{
  struct abstract_write *ignore = make_packet_void();
  struct abstract_write *fail = make_disconnect(connection);
  struct abstract_write *kex = make_client_key_exchange(connection);
  
  struct dispatch_assoc table[] = {
    { SSH_MSG_DISCONNECT, make_handle_disconnect(connection) },
    { SSH_MSG_IGNORE, ignore },
    { SSH_MSG_UNIMPLEMENTED, ignore },
    { SSH_MSG_DEBUG, make_handle_debug(connection) },
    { SSH_MSG_SERVICE_REQUEST, fail },
    { SSH_MSG_SERVICE_ACCEPT, fail },
    { SSH_MSG_KEXINIT, kex },
    { SSH_MSG_NEWKEYS, fail },
    { SSH_MSG

      
#endif
      
