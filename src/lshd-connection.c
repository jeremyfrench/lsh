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
#include "server_session.h"
#include "ssh.h"
#include "ssh_read.h"
#include "ssh_write.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd-connection.c.x"

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
  if (ssh_write_data(connection->writer,
		     global_oop_source, STDOUT_FILENO,
		     ssh_format("%i%S",
				lsh_string_sequence_number(packet),
				packet)) < 0)
    fatal("write_packet: Write failed: %e\n", errno);
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

static void
error_callback(struct error_callback *s UNUSED,
	       int error)
{
  fatal("error_callback:err = %e\n", error);
}

static struct error_callback *
make_error_callback(void)
{
  NEW(error_callback, self);
  self->error = error_callback;
  return self;
}

/* GABA:
   (class
     (name connection_write)
     (super abstract_write)
     (vars
       (connection object connection)))
*/

static void
read_handler(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(connection_write, self, s);
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

static struct abstract_write *
make_connection_read_handler(struct connection *connection)
{
  NEW(connection_write, self);
  self->super.write = read_handler;
  self->connection = connection;
  return &self->super;
}

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
  
  struct error_callback *error = make_error_callback();
  
  self->reader = make_ssh_read_state(8, 8,
				     service_process_header,
				     error);
  ssh_read_packet(self->reader, global_oop_source, STDIN_FILENO,
		  make_connection_read_handler(self));
  ssh_read_start(self->reader, global_oop_source, STDIN_FILENO);

  self->writer = make_ssh_write_state();

  self->table = make_channel_table(make_connection_write_handler(self));

  ALIST_SET(self->table->channel_types, ATOM_SESSION,
	    &make_open_session(
	      make_alist(1, ATOM_SHELL, &shell_request_handler, -1))->super);

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
  fprintf(stderr, "argc = %d\n", argc);
  {
    int i;
    for (i = 0; i < argc; i++)
      fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
  }
      
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  global_oop_source = io_init();

  struct connection *connection;
  werror("Started connection service\n");
  
  connection = make_connection();
  gc_global(&connection->super);

  io_run();
  
  return EXIT_SUCCESS;
}
