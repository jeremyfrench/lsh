/* connection_commands.c
 *
 * $Id$
 */

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

#include "connection_commands.c.x"

/* GABA:
   (class
     (name connection_close_handler)
     (super close_callback)
     (vars
       (connection object ssh_connection)))
*/

static int connection_die(struct close_callback *c, int reason)
{
  CAST(connection_close_handler, closure, c);
  
  verbose("Connection died, for reason %i.\n", reason);
  if (reason != CLOSE_EOF)
    werror("Connection died.\n");

  KILL_RESOURCE_LIST(closure->connection->resources);
  
  return 4711;  /* Ignored */
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

static int do_line(struct line_handler **h,
		   struct read_handler **r,
		   UINT32 length,
		   UINT8 *line)
{
  CAST(connection_line_handler, closure, *h);
  
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      /* NOTE: According to the spec, there's no reason for the server
       * to accept a client that wants version 1.99. But Datafellow's
       * ssh2 client does exactly that, so we have to support it. And
       * I don't think it causes any harm. */
      if ( ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(line + 4, "1.99-", 5)) )
	{
	  struct read_handler *new;	  
#if WITH_SSH1_FALLBACK
	  if (closure->fallback)
	    {
	      int res;
	      
	      assert(closure->mode == CONNECTION_SERVER);
	      
	      /* Sending keyexchange packet was delayed. Do it now */
	      res = initiate_keyexchange(closure->connection,
					 closure->mode);
	      
	      if (LSH_CLOSEDP(res))
		{
		  werror("server.c: do_line: "
			 "Delayed initiate_keyexchange() failed.\n");
		  *h = NULL;
		  
		  return res | LSH_DIE;
		}
	    }
#endif /* WITH_SSH1_FALLBACK */
	  new = 
	    make_read_packet(
	      make_packet_unpad(
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
	  return LSH_OK | LSH_GOON;
	}
#if WITH_SSH1_FALLBACK      
      else if (closure->fallback
	       && (length >= 6)
	       && !memcmp(line + 4, "1.", 2))
	{
	  *h = NULL;
	  return SSH1_FALLBACK(closure->fallback,
			       closure->fd,
			       length, line);
	}
#endif /* WITH_SSH1_FALLBACK */
      else
	{
	  werror("Unsupported protocol version: %ps\n",
		 length, line);

	  /* FIXME: Clean up properly */
	  KILL(closure);
	  *h = NULL;
	  
	  return LSH_FAIL | LSH_DIE;
	}
    }
  else
    {
      /* Display line */
      werror("%ps\n", length, line);

      /* Read next line */
      return LSH_OK | LSH_GOON;
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
  return make_read_line(&closure->super);
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

static int do_connection(struct command *s,
			 struct lsh_object *x,
			 struct command_continuation *c)
{
  CAST(connection_command, self, s);
  CAST(io_fd, fd, x);
  struct lsh_string *version;
  int res;
  
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

  connection_init_io
    (connection, 
     &io_read_write(fd,
		    make_connection_read_line(connection, self->mode,
					      fd->super.fd, self->fallback),
		    self->block_size,
		    make_connection_close_handler(connection))
     ->buffer->super,
     self->random);

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
    return A_WRITE(connection->raw,
		   ssh_format("%lS\n", version));
#endif /* WITH_SSH1_FALLBACK */

  res = A_WRITE(connection->raw,
		ssh_format("%lS\r\n", version));
  if (LSH_CLOSEDP(res))
    return res;
  
  return res | initiate_keyexchange(connection, self->mode);
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
