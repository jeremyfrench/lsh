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
       (c object command_continuation)
       ;; Needed for fallback.
       (fd . int)
       (kex_packets string)
       (fallback object ssh1_fallback)))
*/

static int do_line(struct line_handler **h,
		   struct read_handler **r,
		   UINT32 length,
		   UINT8 *line)
{
  CAST(server_line_handler, closure, *h);
  
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
	      assert(closure->kex_packets);
	      
	      /* Sending keyexchange packet was delayed. Do it now */
	      res = A_WRITE(closure->connection->raw,
			    closure->kex_packets);
	      closure->kex_packets = NULL;
	      
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

	  /* FIXME: Cleanup properly. */

	  *r = new;
	  return COMMAND_RETURN(closure->c, connection);
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

struct read_handler *
make_connection_read_line(struct ssh_connection *connection, int mode,
			  int fd,
			  struct ssh1_fallback *fallback,
			  struct lsh_string *kex_packets,
			  struct command_continuation *c)
{
  NEW(connection_line_handler, closure);

  closure->super.handler = do_line;
  closure->connection = connection;
  closure->mode = mode;
  closure->fd = fd;
  closure->fallback = fallback;
  closure->kex_packets = kex_packets;
  closure->c = c;
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
  struct lsh_string *kex_now;
  struct lsh_string *kex_delayed = NULL;
  
  struct ssh_connection *connection = make_ssh_connection();
  kex_now = MAKE_KEXINIT(closure->init, connection, mode); 

  switch (self->mode)
    {
    case CONNECTION_CLIENT:
      version = ssh_format("SSH-%lz-%lz %lz",
			   CLIENT_PROTOCOL_VERSION,
			   SOFTWARE_CLIENT_VERSION,
			   closure->id_comment);
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
	  kex_delayed = kex_now;
	  kex_now = 0;
	}
      else
	version =
	  ssh_format("SSH-%lz-%lz %lz",
		     SERVER_PROTOCOL_VERSION,
		     SOFTWARE_SERVER_VERSION,
		     self->id_comment);
      break;
    default:
      fatal("do_connection: Internal error\n");
    }

  io_read_write(fd,
		make_connection_read_line(connection, self->mode,
					  fd, self->fallback, kex_delayed,
					  c),
		self->block_size,
		make_connection_close_handler(connection));

  connection->versions[self->mode] = version;

#if WITH_SSH1_FALLBACK
  /* In this mode the server SHOULD NOT send carriage return character (ascii
   * 13) after the version identification string.
   *
   * Furthermore, it should not send any data after the identification string,
   * until the client's identification string is received. */
  if (closure->fallback)
    {
      assert(!kex_now);
      return A_WRITE(connection->raw,
		     ssh_format("%lS\n", version));
    }
#endif /* WITH_SSH1_FALLBACK */

  assert(kex_now);
  return A_WRITE(connection->raw,
		 ssh_format("%lS\r\n%lfS", version, kex_now));
}
