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

#include "lshd.h"

#include "algorithms.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "randomness.h"
#include "server.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "lshd.h.x"
#undef GABA_DEFINE

#include "lshd.c.x"

static oop_source *global_oop_source;

/* FIXME: Duplicated in connection.c */
static const char *packet_types[0x100] =
#include "packet_types.h"
;



/* GABA:
   (class
     (name lshd_read_error)
     (super error_callback)
     (vars
       (connection object lshd_connection)))
*/

static void
lshd_read_error(struct error_callback *s, int error)
{
  CAST(lshd_read_error, self, s);
  werror("Read failed: %e\n", error);
  KILL(&self->connection->super);
}

static struct error_callback *
make_lshd_read_error(struct lshd_connection *connection)
{
  NEW(lshd_read_error, self);
  self->super.error = lshd_read_error;
  self->connection = connection;

  return &self->super;
}


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
make_lshd_connection(struct configuration *config, int input, int output)
{
  NEW(lshd_connection, self);
  init_resource(&self->super, kill_lshd_connection);
  self->config = config;
  self->ssh_input = input;
  self->ssh_output = output;

  init_kexinit_state(&self->kex);
  self->session_id = NULL;

  self->service_state = SERVICE_DISABLED;
  
  self->kexinit_handler = &lshd_kexinit_handler;
  self->newkeys_handler = NULL;
  self->kex_handler = NULL;
  self->service_handler = &lshd_service_request_handler;
  
  self->reader = make_lshd_read_state(make_lshd_process_ssh_header(self),
				      make_lshd_read_error(self));

  self->rec_max_packet = SSH_MAX_PACKET;
  self->rec_mac = NULL;
  self->rec_crypto = NULL;
  self->rec_compress = NULL;

  self->writer = make_ssh_write_state();
  self->send_mac = NULL;
  self->send_crypto = NULL;
  self->send_compress = NULL;
  self->send_seqno = 0;
  
  self->service_fd = -1;

  return self;
};

static void
connection_write_data(struct lshd_connection *connection,
		      struct lsh_string *data)
{
  /* FIXME: Proper error handling */  
  if (ssh_write_data(connection->writer,
		     global_oop_source, connection->ssh_output, data) < 0)
    fatal("Write failed.\n");
}

void
connection_write_packet(struct lshd_connection *connection,
			struct lsh_string *packet)
{
  connection_write_data(connection,
			encrypt_packet(packet,
				       connection->send_compress,
				       connection->send_crypto,
				       connection->send_mac,
				       connection->config->random,
				       connection->send_seqno++));
}

void
connection_disconnect(struct lshd_connection *connection,
		      int reason, const uint8_t *msg)
{
  if (reason)
    connection_write_packet(connection, format_disconnect(reason, msg, ""));
  
  KILL_RESOURCE(&connection->super);
};

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
      connection_disconnect(self->connection, 0, NULL);
      return;
    }

  self->connection->kex.version[0] = line;
  
  self->super.write = lshd_handle_packet;
  
  ssh_read_packet(&self->connection->reader->super,
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

/* Handles all packets to be sent to the service layer. */
DEFINE_PACKET_HANDLER(lshd_service_handler, connection, packet)
{
  if (ssh_write_data(connection->service_writer,
		     global_oop_source, connection->service_fd,
		     ssh_format("%i%fS", lsh_string_sequence_number(packet), packet)) < 0)
    fatal("lshd_service_handler: Write failed.\n");
}

/* GABA:
   (class
     (name lshd_process_service_header)
     (super header_callback)
     (vars
       (connection object lshd_connection)))
*/

static struct lsh_string *
lshd_process_service_header(struct header_callback *s, struct ssh_read_state *state,
			    uint32_t *done)
{
  CAST(lshd_process_service_header, self, s);
  struct lshd_connection *connection = self->connection;
  
  uint32_t seqno;
  uint32_t length;
  struct lsh_string *packet;
  const uint8_t *header;
  
  header = lsh_string_data(state->header);

  seqno = READ_UINT32(header);
  length = READ_UINT32(header + 4);

  if (length > (connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("lshd_process_service_header: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, connection->rec_max_packet);
		  
      connection_disconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
			    "Received too large packet from service layer.");
      return NULL;
    }

  packet = lsh_string_alloc(length);

  /* The sequence number is unused */
  lsh_string_set_sequence_number(packet, seqno);
  *done = 0;
  return packet;
}

static struct header_callback *
make_lshd_process_service_header(struct lshd_connection *connection)
{
  NEW(lshd_process_service_header, self);
  self->super.process = lshd_process_service_header;
  self->connection = connection;

  return &self->super;
}

static void
lshd_service_read_handler(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(lshd_read_handler, self, s);
  struct lshd_connection *connection = self->connection;

  if (!packet)
    {
      /* EOF */
      connection_disconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
			    "Service layer died");      
    }
  else if (!lsh_string_length(packet))
    connection_disconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
			  "Received empty packet from service layer.");

  else
    {
      uint8_t msg = lsh_string_data(packet)[0];
      connection_write_packet(connection, packet);
      if (msg == SSH_MSG_DISCONNECT)
	connection_disconnect(connection, 0, NULL);
    }
}

static struct abstract_write *
make_lshd_service_read_handler(struct lshd_connection *connection)
{
  NEW(lshd_read_handler, self);
  self->super.write = lshd_service_read_handler;
  self->connection = connection;

  return &self->super;
}

/* FIXME: Duplicates server_session.c: lookup_subsystem. */
static const char *
lookup_service(const char **services,
	       uint32_t length, const uint8_t *name)
{
  unsigned i;
  if (memchr(name, 0, length))
    return NULL;

  for (i = 0; services[i]; i+=2)
    {
      assert(services[i+1]);
      if ((length == strlen(services[i]))
	  && !memcmp(name, services[i], length))
	return services[i+1];
    }
  return NULL;
}

DEFINE_PACKET_HANDLER(lshd_service_request_handler, connection, packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  const uint8_t *name;
  uint32_t name_length;

  assert(connection->service_state == SERVICE_ENABLED);
  
  simple_buffer_init(&buffer, STRING_LD(packet));

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_string(&buffer, &name_length, &name)
      && parse_eod(&buffer))
    {
      const char *program = lookup_service(connection->config->services,
					   name_length, name);

      if (program)
	{
	  int pipe[2];
	  pid_t child;
	  
	  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0)
	    {
	      werror("lshd_service_request_handler: socketpair failed: %e\n", errno);
	      connection_disconnect(connection, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				    "Service could not be started");
	      return;
	    }
	  child = fork();
	  if (child < 0)
	    {
	      werror("lshd_service_request_handler: fork failed: %e\n", errno);
	      close(pipe[0]);
	      close(pipe[1]);
	      connection_disconnect(connection, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				    "Service could not be started");
	      return;	      
	    }
	  if (child)
	    {
	      /* Parent process */
	      close(pipe[1]);
	      connection->service_fd = pipe[0];
	      connection->service_handler = &lshd_service_handler;
	      connection->service_state = SERVICE_STARTED;

	      connection->service_reader
		= make_ssh_read_state(8, 8,
				      make_lshd_process_service_header(connection),
				      connection->reader->super.error);
	      ssh_read_packet(connection->service_reader,
			      global_oop_source, connection->service_fd,
			      make_lshd_service_read_handler(connection));
	      ssh_read_start(connection->service_reader,
			     global_oop_source, connection->service_fd);

	      connection->service_writer = make_ssh_write_state();	      
	    }
	  else
	    {
	      /* Child process */
	      close(pipe[0]);
	      dup2(pipe[1], STDIN_FILENO);
	      dup2(pipe[1], STDOUT_FILENO);
	      close(pipe[1]);
	      execl(program, program, NULL);
	      
	      werror("lshd_service_request_handler: exec failed: %e\n", errno);
	      _exit(EXIT_FAILURE);
	    }
	}
      else
	connection_disconnect(connection,
			      SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
			      "Service not available");
    }
  else
    connection_error(connection, "Invalid SERVICE_REQUEST");
    
}

/* Handles decrypted packets. */ 
void
lshd_handle_ssh_packet(struct lshd_connection *connection, struct lsh_string *packet)
{
  uint32_t length = lsh_string_length(packet);
  uint8_t msg;
  
  werror("Received packet: %xS\n", packet);
  if (!length)
    {
      werror("Received empty packet!\n");
      lsh_string_free(packet);
      connection_error(connection, "Empty packet");
      return;
    }

  if (length > connection->rec_max_packet)
    {
      werror("Packet too large!\n");
      connection_error(connection, "Packet too large");
      lsh_string_free(packet);
      return;
    }
  
  msg = lsh_string_data(packet)[0];

  werror("handle_connection: Received packet of type %i (%z)\n",
	 msg, packet_types[msg]);

  /* Messages of type IGNORE, DISCONNECT and DEBUG are always
     acceptable. */
  if (msg == SSH_MSG_IGNORE)
    {
      /* Ignore it */
    }

  else if (msg == SSH_MSG_DISCONNECT)
    connection_disconnect(connection, 0, NULL);

  else if (msg == SSH_MSG_DEBUG)
    {
      /* FIXME: In verbose mode, display message */
    }

  /* Otherwise, behaviour depends on te kex state */
  else switch (connection->kex.state)
    {
    case KEX_STATE_IGNORE:
      connection->kex.state = KEX_STATE_IN_PROGRESS;
      break;
      
    case KEX_STATE_IN_PROGRESS:
      if (msg < SSH_FIRST_KEYEXCHANGE_SPECIFIC
	  || msg >= SSH_FIRST_USERAUTH_GENERIC)
	connection_error(connection, "Unexpected message during key exchange");
      else
	HANDLE_PACKET(connection->kex_handler, connection, packet);

      break;

    case KEX_STATE_NEWKEYS:
      if (msg != SSH_MSG_NEWKEYS)
	connection_error(connection, "NEWKEYS expected");
      else
	HANDLE_PACKET(connection->newkeys_handler, connection, packet);
      break;

    case KEX_STATE_INIT:
      if (msg == SSH_MSG_KEXINIT)
	HANDLE_PACKET(connection->kexinit_handler, connection, packet);

      else if (msg == SSH_MSG_SERVICE_REQUEST)
	{
	  if (connection->service_state != SERVICE_ENABLED)
	    connection_disconnect(connection,
				  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				  "Unexpected service request");
	  else
	    HANDLE_PACKET(connection->service_handler, connection, packet);
	}
      else if (msg >= SSH_FIRST_USERAUTH_GENERIC
	       && connection->service_state == SERVICE_STARTED)
	HANDLE_PACKET(connection->service_handler, connection, packet);

      else
	connection_write_packet(
	  connection,
	  format_unimplemented(lsh_string_sequence_number(packet)));

      break;
    }

  lsh_string_free(packet);
}

static void
lshd_handshake(struct lshd_connection *connection)
{
  connection->kex.version[1] = make_string("SSH-2.0-lshd-ng");

  ssh_read_line(&connection->reader->super, 256,
		global_oop_source, connection->ssh_input,
		make_lshd_handle_line(connection));  
  ssh_read_start(&connection->reader->super,
		 global_oop_source, connection->ssh_input);
		 
  connection_write_data(connection,
			ssh_format("%lS\r\n", connection->kex.version[1]));
  lshd_send_kexinit(connection);
}

/* GABA:
   (class
     (name lshd_port)
     (super resource)
     (vars
       (config object configuration)
       (fd . int)))
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
make_lshd_port(struct configuration *config, int fd)
{
  NEW(lshd_port, self);
  init_resource(&self->super, kill_port);
  self->config = config;
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

  connection = make_lshd_connection(self->config, s, s); 
  gc_global(&connection->super);

  lshd_handshake(connection);

  return OOP_CONTINUE;
}
		 
static struct resource_list *
open_ports(struct configuration *config, int port_number)
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

  port = make_lshd_port(config, s);
  remember_resource(ports, &port->super);

  global_oop_source->on_fd(global_oop_source, s, OOP_READ,
			   lshd_port_accept, port);

  gc_global(&ports->super);
  return ports;
}

static oop_source *global_oop_source;

static struct configuration *
make_configuration(const char *hostkey)
{
  NEW(configuration, self);
  static const char *services[] =
    { "ssh-userauth", "lshd-userauth", NULL };
  
  self->random = make_system_random();
  
  self->algorithms = all_symmetric_algorithms();
  ALIST_SET(self->algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_lshd_dh_handler(make_dh14(self->random))->super);

  self->keys = make_alist(0, -1);
  if (!read_host_key(hostkey, all_signature_algorithms(self->random), self->keys))
    werror("No host key.\n");
  
  self->kexinit = make_simple_kexinit(self->random,
				      make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
				      filter_algorithms(self->keys, default_hostkey_algorithms()),
				      default_crypto_algorithms(self->algorithms),
				      default_mac_algorithms(self->algorithms),
				      default_compression_algorithms(self->algorithms),
				      make_int_list(0, -1));
  self->services = services;
  
  return self;  
}

int
main(int argc UNUSED, char **argv UNUSED)
{
  global_oop_source = io_init();

  open_ports(make_configuration("testsuite/key-1.private"),
	     4711);
  
  io_run();

  return EXIT_SUCCESS;
}
