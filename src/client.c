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

/* FIXME: Why include stdio? */
/* #include <stdio.h> */

#include "client.h"

#include "abstract_io.h"
#include "channel.h"
#include "connection.h"
#include "crypto.h"
#include "debug.h"
#include "encrypt.h"
#include "format.h"
#include "pad.h"
#include "parse.h"
#include "read_line.h"
#include "read_packet.h"
#include "service.h"
#include "ssh.h"
#include "unpad.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

/* Handle connection and initial handshaking. */
struct client_callback
{
  struct fd_callback super;
  struct io_backend *backend;
  UINT32 block_size;
  char *id_comment;

  struct randomness *random;
  struct make_kexinit *init;
  struct packet_handler *kexinit_handler;
};

static int client_initiate(struct fd_callback **c,
			   int fd)
{
  struct client_callback *closure
    = (struct client_callback *) *c;

  int res;
  
  /* FIXME: Should pass a key exchange handler, not NULL! */
  struct ssh_connection *connection
    = make_ssh_connection(closure->kexinit_handler);

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
  
  res = A_WRITE(connection->raw,
		ssh_format("%lS\r\n", connection->client_version));
  if (LSH_CLOSEDP(res))
    return res;

  return res | initiate_keyexchange(connection, CONNECTION_CLIENT,
				    MAKE_KEXINIT(closure->init),
				    NULL);
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

  MDEBUG(closure);
  
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ( ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(line + 4, "1.99-", 5)))
	{
	  struct read_handler *new = make_read_packet
	    (make_packet_unpad
	     (make_packet_debug
	      (&closure->connection->super,
	       "")),
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
  struct client_line_handler *closure;

  NEW(closure);

  closure->super.handler = do_line;
  closure->connection = c;
  
  return make_read_line(&closure->super);
}
  
struct fd_callback *
make_client_callback(struct io_backend *b,
		     char *comment,
		     UINT32 block_size,
		     struct randomness *random,
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler)
  
{
  struct client_callback *connected;

  NEW(connected);

  connected->super.f = client_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  connected->id_comment = comment;

  connected->random = random;
  connected->init = init;
  connected->kexinit_handler = kexinit_handler;

  return &connected->super;
}

static int client_close_die(struct close_callback *closure, int reason)
{
  verbose("Connection died, for reason %d.\n", reason);
  if (reason != CLOSE_EOF)
    werror("Connection died.\n");
  exit(1);
}

struct close_callback *make_client_close_handler(void)
{
  struct close_callback *c;

  NEW(c);

  c->f = client_close_die;

  return c;
}

/* Request a service (for instance ssh-userauth). */
struct accept_service_handler
{
  struct packet_handler super;

  int service_name;
  struct ssh_service *service;
};

static int do_accept_service(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct accept_service_handler *closure = (struct accept_service_handler *) c;

  struct simple_buffer buffer;
  int msg_number;
  int name;

  MDEBUG(closure);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_ACCEPT)
      && parse_atom(&buffer, &name)
      && parse_eod(&buffer)
      && (name == closure->service_name))
    {
      lsh_string_free(packet);
      connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = connection->fail;
      
      return SERVICE_INIT(closure->service, connection);
    }

  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

struct ssh_service *make_accept_service_handler(int service_name,
						struct ssh_service *service)
{
  struct accept_service_handler *closure;

  NEW(closure);
  closure->super.handler = do_accept_service;
  closure->service_name = service_name;
  closure->service = service;

  return &closure->super;
}

struct service_request
{
  struct ssh_service super;

  int service_name;
  struct ssh_service *service;
};


static int do_request_service(struct ssh_service *c,
			      struct ssh_connection *connection)
{
  struct service_request *closure = (struct service_request *) c;
  
  MDEBUG(c);

  connection->dispatch[SSH_MSG_SERVICE_ACCEPT]
    = make_accept_service_handler(closure->service_name,
				  closure->service);
  
  return A_WRITE(connection->write, format_service_request(closure->service_name));
}

struct ssh_service *request_service(int service_name,
				    struct ssh_service *service)
{
  struct service_request *closure;

  NEW(closure);
  closure->super.init = do_request_service;
  closure->service_name = service_name;
  closure->service = service;

  return &closure->super;
}

/* Initiate and manage a session */
struct session
{
  struct ssh_channel super;

  int expect_close;

  UINT32 min_window;
  UINT32 max_window;
  
  /* To access stdio */
  struct io_fd *in;
  struct abstract_write *out;
  struct abstract_write *err;
};

static int client_session_die(struct ssh_channel *c, struct abstract_write *write)
{
  struct session *closure = (struct session *) c;
  
  MDEBUG(closure);

  /* FIXME: Don't die this hard. Should send proper close messages,
   * wait for buffers to be flushed, etc. */
  if (closure->expect_close)
    exit(EXIT_SUCCESS);

  exit(EXIT_FAILURE);
}

/* Recieve channel data */
static int do_recieve(struct ssh_channel *c, struct abstract_write *write,
		      int type, struct lsh_string *data)
{
  struct session *closure = (struct session *) c;
  int res = 0;
  
  MDEBUG(closure);

  if (closure->super.rec_window_size < closure->min_window)
    {
      res = A_WRITE(write, prepare_window_adjust
		    (&closure->super,
		     closure->max_window - closure->super.rec_window_size));
      if (LSH_CLOSEDP(res))
	return res;
    }
  
  switch(type)
    {
    case CHANNEL_DATA:
      return A_WRITE(closure->out, data);
    case CHANNEL_STDERR_DATA:
      return A_WRITE(closure->err, data);
    default:
      fatal("Internal error!\n");
    }
}

/* We have a remote shell */
static int do_shell(struct ssh_channel *c, struct abstract_write *write)
{
  struct session *closure = (struct session *) c;

  MDEBUG(closure);
  
  closure->super.recieve = do_recieve;
  closure->in->handler = read_data
}

/* We have opened a channel of type "session" */
static int do_open_confirm(struct ssh_channel *c, struct abstract_write *write)
{
  struct session *closure = (struct session *) c;

  MDEBUG(closure);

  closure->super.open_confirm = NULL;
  closure->super.open_failure = NULL;

  closure->super.channel_success = do_shell;
  closure->super.channel_failure = client_session_die;

  return A_WRITE(write, format_channel_request(ATOM_SHELL, c, 1, ""));
}

struct ssh_channel *make_session(struct io_fd *in,
				 abstract_write *out, abstract_write *err)
{
  struct session *self;

  NEW(self);

  self->super.request_types = make_alist(0, -1);
  self->super.recieve = NULL;
  self->super.close = NULL;
  self->super.eof = NULL;
  self->super.open_confirm = do_open_confirm;
  self->super.open_failure = client_session_die;
  self->super.channel_success = NULL;
  self->super.channel_failure = NULL;
  
  self->expect_close = 0;
  self->in = in;
  self->out = out;
  self->err = err;

  return &self->super;
}

struct client_startup
{
  struct connection_startup super;

  /* Whether to request pty, forwarding, exec ... */
  int shell;
};

static int do_client_startup(struct connection_startup *c,
			     struct channel_table *table,
			     struct abstract_write *write)
{
  struct client_startup *closure = (struct client_startup *) c;

  MDEBUG(closure);

  A_WRITE(write, prepare_channel_open(table, ATOM_SESSION,
  
}

/* Request opening a session. */
struct connection_startup *make_client_startup(struct io_fd in,
					       struct abstract_write out,
					       struct abstract_write err,
					       int want_shell)
{
  struct client_startup *closure;
  struct ssh_channel *session;
  
  NEW(closure);
  closure->super.start = do_client_startup;
  closure->session = make_session(in, out, err);
  
  closure->shell = want_shell;

  return &closure->super;
}

