/* lshd.c
 *
 * Main server program.
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

#include <assert.h>
#include <string.h>

#include <unistd.h>

#include <netinet/in.h>

#include <oop.h>

#include "nettle/macros.h"

#include "crypto.h"
#include "exception.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "ssh_read.h"
#include "werror.h"
#include "xalloc.h"

enum read_state { READ_UNDEF, READ_LINE, READ_HEADER, READ_PACKET };
struct ssh_read_state;

#include "lshd.c.x"


static oop_source *global_oop_source;

/* GABA:
   (class
     (name lshd_read_state)
     (super ssh_read_state)
     (vars
       (sequence_number . uint32_t);
       (padding . uint8_t)))
*/

static struct lshd_read_state *
make_lshd_read_state(struct header_callback *process,
		     struct exception_handler *e)
{
  NEW(lshd_read_state, self);
  init_ssh_read_state(&self->super, SSH_MAX_BLOCK_SIZE, 8, process, e);
  self->sequence_number = 0;

  return self;
}


/* GABA:
   (class
     (name ssh_process_header)
     (super header_callback)
     (vars
       (sequence_number . uint32_t);
       (connection object lshd_connection)))
*/

static struct lsh_string *
ssh_process_header(struct header_callback *s, struct ssh_read_state *rs,
		   uint32_t *done)
{
  CAST(ssh_process_header, self, s);
  CAST(lshd_read_state, state, rs);
  
  const uint8_t *header;
  uint32_t length;
  uint32_t padding;
  uint32_t block_size;
  uint32_t mac_size;
  struct lsh_string *packet;
  
  block_size = self->connection->rec_crypto
    ? self->connection->rec_crypto->block_size : 8;

  if (self->connection->rec_crypto)
    {
      assert(state->super.header_length == block_size);
      CRYPT(self->connection->rec_crypto,
	    block_size,
	    state->super.header, 0,
	    state->super.header, 0);
    }
  header = lsh_string_data(state->super.header);
  length = READ_UINT32(header);

  /* NOTE: We don't implement a limit at _exactly_
   * rec_max_packet, as we don't include the length field
   * and MAC in the comparison below. */
  if (length > (self->connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("read_packet: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, self->connection->rec_max_packet);
		  
      PROTOCOL_ERROR(self->connection->e, "Packet too large");
      return NULL;
    }

  if ( (length < 12)
       || (length < (block_size - 4))
       || ( (length + 4) % block_size))
    {
      werror("read_packet: Bad packet length %i\n",
	     length);
      PROTOCOL_ERROR(self->connection->e, "Invalid packet length");
      return NULL;
    }
  
  if (self->connection->rec_mac)
    {
      uint8_t s[4];
      WRITE_UINT32(s, self->sequence_number);
      MAC_UPDATE(self->connection->rec_mac, 4, s);
      MAC_UPDATE(self->connection->rec_mac,
		 block_size, header);
    }

  padding = header[4];
  
  if ( (padding < 4)
       || (padding >= length) )
    {
      PROTOCOL_ERROR(self->connection->e,
		     "Bogus padding length.");
      return NULL;
    }
  mac_size = self->connection->rec_mac
    ? self->connection->rec_mac->mac_size : 0;
  
  packet = lsh_string_alloc(length - 1 + mac_size);
  lsh_string_write(packet, 0, block_size - 5, header + 5);
  lsh_string_set_sequence_number(packet, self->sequence_number++);
  
  if (block_size - 5 == length + mac_size)
    {
      werror("Entire paccket fit in first block.\n");
      abort();
#if 0
      /* This can happen only if we're using a cipher with a large
	 block size, and no mac. */
      assert(!self->connection->rec_mac);
      assert(self->connection->rec_crypto);
      lsh_string_trunc(packet, length);
      lshd_handle_ssh_packet(connection, packet);

      return NULL;
#endif
    }

  *done = block_size - 5;
  return packet;
}

static struct header_callback *
make_ssh_process_header(struct lshd_connection *connection)
{
  NEW(ssh_process_header, self);
  self->super.process = ssh_process_header;
  self->connection = connection;

  return &self->super;
}

/* GABA:
   (class
     (name lshd_connection)
     (super resource)
     (vars
       (e object exception_handler)

       ; Sent and received version strings.
       ; Client is index 0, server is index 1.
       (versions array (string) 2)
       
       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)
       (reader object lshd_read_state)
       (rec_max_packet . uint32_t)
       (rec_mac object mac_instance)
       (rec_crypto object crypto_instance)
       (rec_compress object compress_instance)

       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       ; (writer object ...)

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)

       ; Communication with service on top of the transport layer.
       ; This is a bidirectional pipe
       (service_fd . int)
       (service_reader object ssh_read_state)
       ; (service_writer ...)
       ))
*/

static void
kill_lshd_connection(struct resource *s)
{
  CAST(lshd_connection, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;

      global_oop_source->cancel_fd(global_oop_source,
				   self->ssh_input, OOP_READ);
      close(self->ssh_input);
      
      global_oop_source->cancel_fd(global_oop_source,
				   self->ssh_output, OOP_WRITE);

      if (self->ssh_output != self->ssh_input)
	close(self->ssh_output);

      if (self->service_fd != -1)
	{
	  global_oop_source->cancel_fd(global_oop_source,
				       self->service_fd, OOP_READ);
	  global_oop_source->cancel_fd(global_oop_source,
				       self->service_fd, OOP_WRITE);
	  close(self->service_fd);
	}
    }
}

static struct lshd_connection *
make_lshd_connection(int input, int output)
{
  NEW(lshd_connection, self);
  init_resource(&self->super, kill_lshd_connection);
  self->ssh_input = input;
  self->ssh_output = output;

  /* FIXME: Exceptions. All it needs to do is to close the connection.
     We probably don't need any exceptions at all, as the right action
     for any errors is to close the corresponding connection. We
     probably don't even need to kill the child process, as it should
     get EOF. */
  self->e = &default_exception_handler;
  self->version[0] = self->version[1] = NULL;
  
  self->reader = make_lshd_read_state(make_ssh_process_header(self),
				      self->e);
  self->rec_max_packet = SSH_MAX_PACKET;
  self->rec_mac = NULL;
  self->rec_crypto = NULL;
  self->rec_compress = NULL;

  self->send_mac = NULL;
  self->send_crypto = NULL;
  self->send_compress = NULL;
  
  self->service_fd = -1;

  return self;
};

/* GABA:
   (class
     (name lshd_read_handler)
     (super abstract_write)
     (vars
       (connection object lshd_connection)))
*/

static void
lshd_handle_packet(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(lshd_read_handler, self, s);
  werror("Received packet: %xS\n", packet);
  lsh_string_free(packet);

  ssh_read_header(&self->connection->reader->super,
		  global_oop_source, self->connection->ssh_input,
		  &self->super);
}

#if 0
static struct abstract_write *
make_lshd_handle_packet(struct lshd_connection *connection)
{
  NEW(lshd_read_handler, self);
  self->connection = connection;
  self->super.write = lshd_handle_packet;
  return &self->super;
}
#endif

static void
lshd_handle_line(struct abstract_write *s, struct lsh_string *line)
{
  CAST(lshd_read_handler, self, s);
  const uint8_t *version;
  uint32_t length;
  
  verbose("Client version string: %pS\n", line);

  length = lsh_string_length(line);
  version = lsh_string_data(line);

  /* Line must start with "SSH-2.0-" (we may need to allow "SSH-1.99" as well). */
  if (length < 8 || 0 != memcmp(version, "SSH-2.0-", 4))
    {
      PROTOCOL_ERROR_DISCONNECT(self->connection->e, 0, "Invalid version line");
      return;
    }

  self->connection->version[0] = line;
  
  self->super.write = lshd_handle_packet;
  
  ssh_read_header(&self->connection->reader->super,
		  global_oop_source, self->connection->ssh_input,
		  &self->super);
}

static struct abstract_write *
make_lshd_handle_line(struct lshd_connection *connection)
{
  NEW(lshd_read_handler, self);
  self->connection = connection;
  self->super.write = lshd_handle_line;
  return &self->super;
}

static void
lshd_handshake(struct lshd_connection *connection)
{
  connection->version[1] = make_string("SSH-2.0-lshd-ng");
  
  if (write_raw(connection->ssh_output,
		16, "SSH-2.0-lshd-ng\n"))
    fatal("Writing greeting failed.\n");

  ssh_read_line(&connection->reader->super, 256,
		global_oop_source, connection->ssh_input,
		make_lshd_handle_line(connection));  
}

/* GABA:
   (class
     (name lshd_port)
     (super resource)
     (vars
       (fd . int)
       ; To we need any options?
       ))
*/

static void
kill_port(struct resource *s)
{
  CAST(lshd_port, self, s);

  if (self->super.alive)
    {
      self->super.alive = 0;
      global_oop_source->cancel_fd(global_oop_source, self->fd, OOP_WRITE);
      close(self->fd);
    }
};

static struct lshd_port *
make_lshd_port(int fd)
{
  NEW(lshd_port, self);
  init_resource(&self->super, kill_port);
  self->fd = fd;
  
  return self;
}

static void *
lshd_port_accept(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST(lshd_port, self, (struct lsh_object *) state);
  struct lshd_connection *connection;
  struct sockaddr_in peer;
  socklen_t peer_length = sizeof(peer);
  int s;
  
  assert(event == OOP_READ);
  assert(self->fd == fd);

  s = accept(self->fd, (struct sockaddr *) &peer, &peer_length);
  if (s < 0)
    {
      werror("accept faild: %e\n", errno);
      return OOP_CONTINUE;
    }

  connection = make_lshd_connection(s, s); 
  gc_global(&connection->super);

  lshd_handshake(connection);

  return OOP_CONTINUE;
}
		 
static struct resource_list *
open_ports(int port_number)
{
  struct resource_list *ports = make_resource_list();
  struct sockaddr_in sin;
  struct lshd_port *port;
  int yes = 1;
  int s;
  
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    fatal("socket failed: %e\n", errno);

  io_set_nonblocking(s);
  io_set_close_on_exec(s);

  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) <0)
    fatal("setsockopt SO_REUSEADDR failed: %e\n", errno);
  
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(port_number);

  if (bind(s, &sin, sizeof(sin)) < 0)
    fatal("bind failed: %e\n", errno);

  if (listen(s, 256) < 0)
    fatal("listen failed: %e\n", errno);

  port = make_lshd_port(s);
  remember_resource(ports, &port->super);

  global_oop_source->on_fd(global_oop_source, s, OOP_READ,
			   lshd_port_accept, port);

  gc_global(&ports->super);
  return ports;
}

static oop_source *global_oop_source;

int
main(int argc UNUSED, char **argv UNUSED)
{
  global_oop_source = io_init();

  open_ports(4711);
  
  io_run();

  return EXIT_SUCCESS;
}
