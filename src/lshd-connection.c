/* lshd-connection.c
 *
 * Main program for the ssh-connection service.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include <oop.h>

#include "channel.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "reaper.h"
#include "server_session.h"
#include "ssh.h"
#include "ssh_read.h"
#include "ssh_write.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd-connection.c.x"

#define CONNECTION_WRITE_THRESHOLD 1000
#define CONNECTION_WRITE_BUFFER_SIZE (100*SSH_MAX_PACKET)

oop_source *global_oop_source;

/* GABA:
   (class
     (name connection)
     (super resource)
     (vars
       (reader object ssh_read_state)
       (writer object ssh_write_state)
       (table object channel_table)))
*/

static void
kill_connection(struct resource *s)
{
  CAST(connection, self, s);
  werror("kill_connection\n");
  exit(EXIT_FAILURE);
}

static void
write_packet(struct connection *connection,
	     struct lsh_string *packet)
{
  /* FIXME: Go to sleep if ssh_write_data returns 0? */
  enum ssh_write_status status;

  packet = ssh_format("%i%S",
		      lsh_string_sequence_number(packet),
		      packet);
  
  status = ssh_write_data(connection->writer,
			  STDOUT_FILENO, SSH_WRITE_FLAG_PUSH, 
			  STRING_LD(packet));
  lsh_string_free(packet);

  switch (status)
    {
    case SSH_WRITE_IO_ERROR:
      werror("write_packet: Write failed: %e\n", errno);
      exit(EXIT_FAILURE);
    case SSH_WRITE_OVERFLOW:
      werror("write_packet: Buffer fill\n", errno);
      exit(EXIT_FAILURE);
      
      /* FIXME: Implement some flow control. Or use some different
	 writer with unbounded buffers? */
    }
}

static void
disconnect(struct connection *connection, const char *msg)
{
  werror("disconnecting: %z.\n", msg);

  write_packet(connection,
	       format_disconnect(SSH_DISCONNECT_BY_APPLICATION,
				 msg, ""));
  exit(EXIT_FAILURE);
}

/* GABA:
   (class
     (name connection_read_state)
     (super ssh_read_state)
     (vars
       (connection object connection)))
*/

static void
error_handler(struct ssh_read_state *s UNUSED, int error)
{
  werror("Read failed: %e\n", error);
  exit(EXIT_FAILURE);
}

static void
read_handler(struct ssh_read_state *s, struct lsh_string *packet)
{
  CAST(connection_read_state, self, s);
  uint8_t msg;

  werror("read_handler: Received packet %xS\n", packet);

  if (!lsh_string_length(packet))
    disconnect(self->connection,
	       "lshd-connection received an empty packet");
  
  msg = lsh_string_data(packet)[0];

  if (msg < SSH_FIRST_USERAUTH_GENERIC)
    /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
    disconnect(self->connection,
	       "lshd-connection received a transport layer packet");

  if (msg < SSH_FIRST_CONNECTION_GENERIC)
    {
      /* Ignore */
    }
  else
    channel_packet_handler(self->connection->table, packet);

  lsh_string_free(packet);
}

static struct ssh_read_state *
make_connection_read_state(struct connection *connection)
{
  NEW(connection_read_state, self);
  init_ssh_read_state(&self->super, 8, 8, service_process_header, error_handler);
  self->connection = connection;
  return &self->super;
}


/* GABA:
   (class
     (name connection_write)
     (super abstract_write)
     (vars
       (connection object connection)))
*/

static void
write_handler(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(connection_write, self, s);

  write_packet(self->connection, packet);
}

static struct abstract_write *
make_connection_write_handler(struct connection *connection)
{
  NEW(connection_write, self);
  self->super.write = write_handler;
  self->connection = connection;
  return &self->super;
}

static struct connection *
make_connection(void)
{
  NEW(connection, self);
  init_resource(&self->super, kill_connection);
  
  self->reader = make_connection_read_state(self);
  ssh_read_packet(self->reader, global_oop_source, STDIN_FILENO,
		  read_handler);
  ssh_read_start(self->reader, global_oop_source, STDIN_FILENO);

  self->writer = make_ssh_write_state(CONNECTION_WRITE_BUFFER_SIZE,
				      CONNECTION_WRITE_THRESHOLD);

  self->table = make_channel_table(make_connection_write_handler(self));

  /* FIXME: Always enables X11 */
  ALIST_SET(self->table->channel_types, ATOM_SESSION,
	    &make_open_session(
	      make_alist(3,
			 ATOM_SHELL, &shell_request_handler,
			 ATOM_PTY_REQ, &pty_request_handler,
			 ATOM_X11_REQ, &x11_request_handler, -1))->super);

  return self;
}

/* Option parsing */

const char *argp_program_version
= "lshd-connection (lsh-" VERSION "), secsh protocol version " SERVER_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ NULL, NULL,
  NULL,
  "Handles the ssh-connection service.\v"
  "Intended to be invoked by lshd and lshd-userauth.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{
  struct connection *connection;
  fprintf(stderr, "argc = %d\n", argc);
  {
    int i;
    for (i = 0; i < argc; i++)
      fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
  }
      
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  global_oop_source = io_init();
  reaper_init();

  werror("Started connection service\n");
  
  connection = make_connection();
  gc_global(&connection->super);

  io_run();
  
  return EXIT_SUCCESS;
}
