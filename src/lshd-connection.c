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
#include "ssh_read.h"
#include "ssh_write.h"
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
  werror("read_handler: Got packet %xS\n", packet);
  lsh_string_free(packet);

  /* FIXME: XXX */
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

  if (ssh_write_data(self->connection->writer,
		     global_oop_source, STDOUT_FILENO,
		     ssh_format("%i%S",
				lsh_string_sequence_number(packet),
				packet)) < 0)
    fatal("write_handler: Write failed.\n");
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

  return self;
}

int
main(int argc, char **argv)
{
  global_oop_source = io_init();

  struct connection *connection;
  werror("Started connection service\n");
  
  connection = make_connection();
  gc_global(&connection->super);

  io_run();
  
  return EXIT_SUCCESS;
}
