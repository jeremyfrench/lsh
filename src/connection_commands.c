/* connection_commands.c
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "connection_commands.h"

#include "compress.h"
#include "connection.h"
#include "debug.h"
#include "format.h"
#include "io.h"
#include "read_line.h"
#include "read_packet.h"
#include "ssh.h"
#include "unpad.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#include "connection_commands.c.x"

/* GABA:
   (class
     (name connection_close_handler)
     (super close_callback)
     (vars
       (connection object ssh_connection)))
*/

static void
connection_die(struct close_callback *c, int reason)
{
  CAST(connection_close_handler, closure, c);
  
  verbose("Connection died, for reason %i.\n", reason);
  if (reason != CLOSE_EOF)
    werror("Connection died.\n");

  KILL_RESOURCE_LIST(closure->connection->resources);
}

struct close_callback *make_connection_close_handler(struct ssh_connection *c)
{
  NEW(connection_close_handler, closure);

  closure->connection = c;  
  closure->super.f = connection_die;

  return &closure->super;
}

/* GABA:
   (class
     (name connection_line_handler)
     (super line_handler)
     (vars
       (connection object ssh_connection)
       (mode . int)
       ;; Needed for fallback.
       (fd . int)
       (fallback object ssh1_fallback)))
*/

/* Returns -1 if the line is not the start of a SSH handshake,
 * 0 if the line appears to be an SSH handshake, but with bogus version fields,
 * or 1 if the line was parsed sucessfully. */
static int
split_version_string(UINT32 length, UINT8 *line,
		     UINT32 *protover_len, UINT8 **protover,
		     UINT32 *swver_len, UINT8 **swver,
		     UINT32 *comment_len, UINT8 **comment)
{
  UINT8 *sep;

  if (length < 4 || memcmp(line, "SSH-", 4) != 0)
    {
      /* not an ssh identification string */
      return -1;
    }
  line += 4; length -= 4;
  sep = memchr(line, '-', length);
  if (!sep)
    {
      return 0;
    }
  *protover_len = sep - line;
  *protover = line;
  
  line = sep + 1;
  length -= *protover_len + 1;

  /* FIXME: The spec is not clear about the separator here. Can there
   * be other white space than a single space character? */
  sep = memchr(line, ' ', length);
  if (!sep)
    {
      *swver_len = length;
      *swver = line;
      *comment = NULL;
      *comment_len = 0;
      return 1;
    }

  *swver_len = sep - line;
  *swver = line;
  *comment = sep + 1;
  *comment_len = length - *swver_len - 1;
  return 1;
}

static void
do_line(struct line_handler **h,
	struct read_handler **r,
	UINT32 length,
	UINT8 *line,
	struct exception_handler *e)
{
  CAST(connection_line_handler, closure, *h);
  UINT32 protover_len, swver_len, comment_len;
  UINT8 *protover, *swver, *comment;
  
  switch(split_version_string(length, line, 
			      &protover_len, &protover, 
			      &swver_len, &swver,
			      &comment_len, &comment))
    {
    case 1:
      {
	/* Parse and remember format string */
	/* NOTE: According to the spec, there's no reason for the server
	 * to accept a client that wants version 1.99. But Datafellow's
	 * ssh2 client does exactly that, so we have to support it. And
	 * I don't think it causes any harm. */
	
	if ( ((protover_len >= 3) && !memcmp(protover, "2.0", 3))
	     || ((protover_len == 4) && !memcmp(protover, "1.99", 4)) )
	  {
	    struct read_handler *new;	  
#if WITH_SSH1_FALLBACK
	    if (closure->fallback)
	      {
		assert(closure->mode == CONNECTION_SERVER);
	      
		/* Sending keyexchange packet was delayed. Do it now */
		initiate_keyexchange(closure->connection,
				     closure->mode);
	      }
#endif /* WITH_SSH1_FALLBACK */

#if DATAFELLOWS_WORKAROUNDS
	    if ( (swver_len > 6) && !memcmp(swver, "2.0.", 4)
		 /* FIXME: Perhaps do a numerical comparison here? */
		 && (memcmp(swver + 4, "13", 2) <= 0) )
	      {
		closure->connection->peer_flags
		  |= (PEER_SSH_DSS_KLUDGE | PEER_SERVICE_ACCEPT_KLUDGE
		      | PEER_USERAUTH_REQUEST_KLUDGE | PEER_SEND_NO_DEBUG);
	      }
#endif	    
	    
	    new = 
	      make_read_packet(
		make_packet_unpad(
		  closure->connection,
		  make_packet_inflate(
		    make_packet_debug(&closure->connection->super, "received"),
		    closure->connection
		    )
		  ),
		closure->connection
		);
	    
	    closure->connection->versions[!closure->mode]
	      = ssh_format("%ls", length, line);

	    verbose("Client version: %pS\n"
		    "Server version: %pS\n",
		    closure->connection->versions[CONNECTION_CLIENT],
		    closure->connection->versions[CONNECTION_SERVER]);

	    *r = new;
	    return;
	  }
#if WITH_SSH1_FALLBACK      
      else if (closure->fallback
	       && (protover_len >= 2)
	       && !memcmp(protover, "1.", 2))
	{
	  *h = NULL;
	  SSH1_FALLBACK(closure->fallback,
			closure->fd,
			length, line,
			e);

	  return;
	}
#endif /* WITH_SSH1_FALLBACK */
      else
	{
	  werror("Unsupported protocol version: %ps\n",
		 length, line);

	  /* FIXME: Clean up properly */
	  KILL(closure);
	  *h = NULL;

	  EXCEPTION_RAISE(closure->connection->e,
			  make_protocol_exception
			  (SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
			   NULL));
	  return;
	}
	fatal("Internal error!\n");
      }
    case 0:
      werror("Incorrectly formatted version string: %s\n", length, line);
      KILL(closure);
      *h = NULL;
      
      PROTOCOL_ERROR(closure->connection->e,
		     "Incorrectly version string.");
      
      return;
    case -1:
      /* Display line */
      werror("%ps\n", length, line);

      /* Read next line */
      break;
    default:
      fatal("Internal error!\n");
    }
}

static struct read_handler *
make_connection_read_line(struct ssh_connection *connection, int mode,
			  int fd,
			  struct ssh1_fallback *fallback)
{
  NEW(connection_line_handler, closure);

  closure->super.handler = do_line;
  closure->connection = connection;
  closure->mode = mode;
  closure->fd = fd;
  closure->fallback = fallback;
  return make_read_line(&closure->super, connection->e);
}

/* Takes a fd as argument, and returns a connection object. Never
 * returns NULL; if the handshaking failes, it won't return at all. */
/* GABA:
   (class
     (name connection_command)
     (super command)
     (vars
       ; CONNECTION_SERVER or CONNECTION_CLIENT
       (mode . int)
       (block_size simple UINT32)
       (id_comment simple "const char *")

       (random object randomness)
       (algorithms object alist)
       
       (init object make_kexinit)
       
       ;; Used only on the server
       (fallback object ssh1_fallback)))
*/

/* Buffer size when reading from the socket */
#define BUF_SIZE (1<<14)

static void
do_connection(struct command *s,
	      struct lsh_object *x,
	      struct command_continuation *c,
	      struct exception_handler *e)
{
  CAST(connection_command, self, s);
  CAST(io_fd, fd, x);
  struct lsh_string *version;
  
  struct ssh_connection *connection = make_ssh_connection(c);

  switch (self->mode)
    {
    case CONNECTION_CLIENT:
      version = ssh_format("SSH-%lz-%lz %lz",
			   CLIENT_PROTOCOL_VERSION,
			   SOFTWARE_CLIENT_VERSION,
			   self->id_comment);
      break;
    case CONNECTION_SERVER:
#if WITH_SSH1_FALLBACK
      if (self->fallback)
	{
	  version =
	    ssh_format("SSH-%lz-%lz %lz",
		       SSH1_SERVER_PROTOCOL_VERSION,
		       SOFTWARE_SERVER_VERSION,
		       self->id_comment);
	}
      else
#endif
	version =
	  ssh_format("SSH-%lz-%lz %lz",
		     SERVER_PROTOCOL_VERSION,
		     SOFTWARE_SERVER_VERSION,
		     self->id_comment);
      break;
    default:
      fatal("do_connection: Internal error\n");
    }

  /* Installing the right exception handler is a little tricky. The
   * passed in handler is typically the top-level handler provided by
   * lsh.c or lshd.c. On top of this, we add the io_exception_handler
   * which takes care of EXC_FINISH_READ exceptions and closes the
   * connection's socket. And on top of this, we have a
   * connection_exception handler, which takes care of EXC_PROTOCOL
   * exceptions, sends a disconnect message, and then raises an
   * EXC_FINISH_READ exception. */
  connection_init_io
    (connection, 
     &io_read_write(fd,
		    make_buffered_read
		    (BUF_SIZE,
		     make_connection_read_line(connection, self->mode,
					       fd->super.fd, self->fallback)),
		    self->block_size,
		    make_connection_close_handler(connection))
     ->write_buffer->super,
     self->random,
     make_exc_finish_read_handler(&fd->super, e, HANDLER_CONTEXT));

  connection->versions[self->mode] = version;
  connection->kexinits[self->mode] = MAKE_KEXINIT(self->init); 
  connection->dispatch[SSH_MSG_KEXINIT]
    = make_kexinit_handler(self->mode, self->init, self->algorithms);

#if WITH_SSH1_FALLBACK
  /* In this mode the server SHOULD NOT send carriage return character (ascii
   * 13) after the version identification string.
   *
   * Furthermore, it should not send any data after the identification string,
   * until the client's identification string is received. */
  if (self->fallback)
    {
      A_WRITE(connection->raw,
	      ssh_format("%lS\n", version));
      return;
    }
#endif /* WITH_SSH1_FALLBACK */

  A_WRITE(connection->raw,
	  ssh_format("%lS\r\n", version));
  
  initiate_keyexchange(connection, self->mode);
}

struct command *
make_handshake_command(int mode,
		       const char *id,
		       UINT32 block_size,
		       struct randomness *r,
		       struct alist *algorithms,
		       struct make_kexinit *init,
		       struct ssh1_fallback *fallback)
{
  NEW(connection_command, self);
  self->mode = mode;
  self->id_comment = id;
  self->block_size = block_size;
  self->random = r;
  self->algorithms = algorithms;
  self->init = init;
  self->fallback = fallback;

  self->super.call = do_connection;
  return &self->super;
}

/* GABA:
   (class
     (name connection_remember_command)
     (super command)
     (vars
       (connection object ssh_connection)))
*/

#if 0
static int do_connection_remember(struct command *s,
				  struct lsh_object *x,
				  struct command_continuation *c)
{
  CAST(connection_remember_command, self, s);
  CAST_SUBTYPE(resource, resource, x);

  if (resource)
    REMEMBER_RESOURCE(self->connection->resources, resource);

  return COMMAND_RETURN(c, resource);
}

static struct lsh_object *
collect_connection_remember(struct collect_info_1 *info,
			     struct lsh_object *x)
{
  CAST(ssh_connection, connection, x);
  NEW(connection_remember_command, self);

  assert(!info->next);

  self->super.call = do_connection_remember;
  self->connection = connection;

  return &self->super.super;
}

struct command connection_remember_command =
STATIC_COMMAND(collect_connection_remember);

#endif

