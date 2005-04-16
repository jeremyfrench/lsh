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

#include <signal.h>

#include <unistd.h>
#include <netinet/in.h>

#include <oop.h>

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
#include "version.h"
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

/* Error callbacks for reading */
static void
lshd_read_error(struct ssh_read_state *s, int error)
{
  CAST(lshd_read_state, self, s);
  werror("Read failed: %e\n", error);
  KILL(&self->connection->super);
}

static void
lshd_protocol_error(struct transport_read_state *s, int reason, const char *msg)
{
  CAST(lshd_read_state, self, s);
  connection_disconnect(self->connection, reason, msg);
}

struct lshd_read_state *
make_lshd_read_state(struct lshd_connection *connection)
{
  NEW(lshd_read_state, self);
  init_transport_read_state(&self->super, SSH_MAX_PACKET,
			    lshd_read_error, lshd_protocol_error);

  self->connection = connection;

  return self;
}


/* Connection */
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

  self->newkeys_handler = NULL;
  self->kex_handler = NULL;

  self->reader = make_lshd_read_state(self);

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
  if (!connection->super.alive)
    {
      werror("connection_write_data: Connection is dead.\n");
      lsh_string_free(data);
      return;
    }
  /* FIXME: If ssh_write_data returns 0, we need to but the connection
     to sleep and wake it up later. */
  if (ssh_write_data(connection->writer,
		     global_oop_source, connection->ssh_output, data) < 0)
    {
      werror("write failed: %e\n", errno);
      connection_disconnect(connection, 0, NULL);
    }
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

static void
lshd_handle_line(struct ssh_read_state *s, struct lsh_string *line)
{
  CAST(lshd_read_state, self, s);
  const uint8_t *version;
  uint32_t length;

  verbose("Client version string: %pS\n", line);

  length = lsh_string_length(line);
  version = lsh_string_data(line);

  /* Line must start with "SSH-2.0-" (we may need to allow "SSH-1.99"
     as well). */
  if (length < 8 || 0 != memcmp(version, "SSH-2.0-", 4))
    {
      connection_disconnect(self->connection, 0, NULL);
      return;
    }

  self->connection->kex.version[0] = line;

  transport_read_packet(&self->super,
			global_oop_source, self->connection->ssh_input,
			lshd_handle_ssh_packet);
}

/* Handles all packets to be sent to the service layer. */
static void
lshd_service_handler(struct lshd_connection *connection, struct lsh_string *packet)
{
  if (ssh_write_data(connection->service_writer,
		     global_oop_source, connection->service_fd,
		     ssh_format("%i%S",
				lsh_string_sequence_number(packet),
				packet)) < 0)
    {
      connection_disconnect(connection,
			    SSH_DISCONNECT_BY_APPLICATION,
			    "Connection to service layer failed.");
    }
}

static void
lshd_service_read_handler(struct ssh_read_state *s, struct lsh_string *packet)
{
  CAST(lshd_service_read_state, self, s);
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

static void
service_read_error(struct ssh_read_state *s, int error)
{
  CAST(lshd_service_read_state, self, s);
  werror("Read from service layer failed: %e\n", error);

  connection_disconnect(self->connection, SSH_DISCONNECT_BY_APPLICATION,
			"Read from service layer failed.");  
}

struct lshd_service_read_state *
make_lshd_service_read_state(struct lshd_connection *connection)
{
  NEW(lshd_service_read_state, self);
  init_ssh_read_state(&self->super, 8, 8, service_process_header, service_read_error);
  self->connection = connection;

  return self;
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

static struct lsh_string *
format_service_accept(uint32_t name_length, const uint8_t *name)
{
  return ssh_format("%c%s", SSH_MSG_SERVICE_ACCEPT, name_length, name);
};

static void
lshd_service_request_handler(struct lshd_connection *connection, struct lsh_string *packet)
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
	      connection->service_state = SERVICE_STARTED;

	      connection->service_reader
		= make_lshd_service_read_state(connection);
	      ssh_read_packet(&connection->service_reader->super,
			      global_oop_source, connection->service_fd,
			      lshd_service_read_handler);
	      ssh_read_start(&connection->service_reader->super,
			     global_oop_source, connection->service_fd);

	      connection->service_writer = make_ssh_write_state();

	      connection_write_packet(connection,
				      format_service_accept(name_length, name));
	    }
	  else
	    {
	      /* Child process */
	      struct lsh_string *hex;
	      
	      close(pipe[0]);
	      dup2(pipe[1], STDIN_FILENO);
	      dup2(pipe[1], STDOUT_FILENO);
	      close(pipe[1]);

	      hex = ssh_format("%lxS", connection->session_id);

	      /* FIXME: Pass sufficient information so that
		 $SSH_CLIENT can be set properly. */
	      execl(program, program, "--session-id", lsh_string_data(hex), NULL);

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

/* Handles decrypted packets. The various handler functions called
   from here should *not* free the packet. FIXME: Better to change
   this? */
void
lshd_handle_ssh_packet(struct transport_read_state *s, struct lsh_string *packet)
{
  CAST(lshd_read_state, self, s);
  struct lshd_connection *connection = self->connection;
  
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

  if (length > connection->reader->super.max_packet)
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
	lshd_kexinit_handler(connection, packet);

      else if (msg == SSH_MSG_SERVICE_REQUEST)
	{
	  if (connection->service_state != SERVICE_ENABLED)
	    connection_disconnect(connection,
				  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				  "Unexpected service request");
	  else
	    lshd_service_request_handler(connection, packet);
	}
      else if (msg >= SSH_FIRST_USERAUTH_GENERIC
	       && connection->service_state == SERVICE_STARTED)
	lshd_service_handler(connection, packet);

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

  ssh_read_line(&connection->reader->super.super, 256,
		global_oop_source, connection->ssh_input,
		lshd_handle_line);
  ssh_read_start(&connection->reader->super.super,
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
      werror("accept failed: %e\n", errno);
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
    {
      werror("socket failed: %e\n", errno);
      return NULL;
    }

  io_set_nonblocking(s);
  io_set_close_on_exec(s);

  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) <0)
    werror("setsockopt SO_REUSEADDR failed: %e\n", errno);

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(port_number);

  if (bind(s, &sin, sizeof(sin)) < 0)
    {
      werror("bind failed: %e\n", errno);
      return NULL;
    }

  if (listen(s, 256) < 0)
    {
      werror("listen failed: %e\n", errno);
      return NULL;
    }
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

  if (!self->random)
    {
      werror("No randomness generator available.\n");
      exit(EXIT_FAILURE);
    }

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

/* Option parsing */

const char *argp_program_version
= "lshd (lsh-" VERSION "), secsh protocol version " SERVER_PROTOCOL_VERSION;

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
  "Server for the ssh-2 protocol.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{  
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  global_oop_source = io_init();

  werror("Listening on port 4711\n");
  if (!open_ports(make_configuration("testsuite/key-1.private"),
		  4711))
    return EXIT_FAILURE;

  /* Ignore status from child processes */
  signal(SIGCHLD, SIG_IGN);
  
  io_run();

  return EXIT_SUCCESS;
}
