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
#include "service.h"
#include "ssh.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "lshd.h.x"
#undef GABA_DEFINE

#include "lshd.c.x"

#define SERVICE_WRITE_THRESHOLD 1000
#define SERVICE_WRITE_BUFFER_SIZE (3 * SSH_MAX_PACKET)

/* Connection */
static void
kill_lshd_connection(struct resource *s)
{
  CAST(lshd_connection, self, s);
  if (self->super.super.alive)
    {
      oop_source *source = self->super.ctx->oop;
      if (self->service_fd != -1)
	{
	  source->cancel_fd(source, self->service_fd, OOP_READ);
	  source->cancel_fd(source, self->service_fd, OOP_WRITE);
	  close(self->service_fd);
	  self->service_fd = -1;
	}
      transport_kill(&self->super);
    }
}

static int
lshd_packet_handler(struct transport_connection *connection,
		    uint32_t seqno, uint32_t length, const uint8_t *packet);

static void
lshd_service_start_read(struct lshd_connection *self);

static void
lshd_service_stop_read(struct lshd_connection *self);

static void
lshd_service_start_write(struct lshd_connection *self);

static void
lshd_service_stop_write(struct lshd_connection *self);

static int
lshd_event_handler(struct transport_connection *connection,
		   enum transport_event event)
{
  CAST(lshd_connection, self, connection);
  switch (event)
    {
    case TRANSPORT_EVENT_START_APPLICATION:
      if (self->service_state == SERVICE_STARTED)
	lshd_service_start_read(self);
      break;
    case TRANSPORT_EVENT_STOP_APPLICATION:
      if (self->service_state == SERVICE_STARTED)
	lshd_service_stop_read(self);
      break;
    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      assert(self->service_state == SERVICE_DISABLED);
      self->service_state = SERVICE_ENABLED;
      connection->packet_handler = lshd_packet_handler;
      break;
    case TRANSPORT_EVENT_CLOSE:
      /* FIXME: Should allow service buffer to drain. */
      if (self->service_fd >= 0)
	{
	  lshd_service_stop_read(self);
	  close(self->service_fd);
	  self->service_fd = -1;
	}
      break;
    case TRANSPORT_EVENT_PUSH:
      if (self->service_state == SERVICE_STARTED
	  && self->service_fd >= 0)
	{
	  enum ssh_write_status status;

	  status = ssh_write_flush(self->service_writer, self->service_fd);

	  switch(status)
	    {
	    case SSH_WRITE_IO_ERROR:
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_BY_APPLICATION,
				   "Connection to service layer failed.");
	      break;
	    case SSH_WRITE_OVERFLOW:
	      werror("Overflow from ssh_write_flush! Should not happen.\n");
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_BY_APPLICATION,
				   "Service layer not responsive.");
	      break;
	    case SSH_WRITE_PENDING:
	      lshd_service_start_write(self);

	    case SSH_WRITE_COMPLETE:
	      lshd_service_stop_write(self);
	      break;
	    }
	}
    }
  return 0;
}

static struct lshd_connection *
make_lshd_connection(struct configuration *config, int input, int output)
{
  NEW(lshd_connection, self);
  init_transport_connection(&self->super, kill_lshd_connection,
			    &config->super,
			    input, output,
			    lshd_event_handler);
  self->service_state = SERVICE_DISABLED;
  self->service_fd = -1;
  self->service_reader = NULL;
  self->service_read_active = 0;
  self->service_write_active = 0;
  self->service_writer = NULL;

  return self;
};

static void
lshd_line_handler(struct transport_connection *connection,
		  uint32_t length, const uint8_t *line)
{
  verbose("Client version string: %ps\n", length, line);

  /* Line must start with "SSH-2.0-" (we may need to allow "SSH-1.99"
     as well). */
  if (length < 8 || 0 != memcmp(line, "SSH-2.0-", 4))
    {
      transport_disconnect(connection, 0, "Bad version string.");
      return;
    }

  connection->kex.version[0] = ssh_format("%ls", length, line);
  connection->line_handler = NULL;
}


/* Communication with service layer */

static void *
oop_read_service(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST(lshd_connection, self, (struct lsh_object *) state);

  assert(fd == self->service_fd);
  assert(event == OOP_READ);

  while (self->service_fd >= 0)
    {
      enum service_read_status status;
      uint32_t seqno;
      uint32_t length;
      const uint8_t *packet;
      const char *msg;

      status = service_read_packet(self->service_reader, fd, &msg,
				   &seqno, &length, &packet);
      switch (status)
	{
	case SERVICE_READ_IO_ERROR:
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Read from service layer failed.");
	  break;
	case SERVICE_READ_PROTOCOL_ERROR:
	  werror("Invalid data from service layer: %z\n", msg);
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Invalid data from service layer.");
	  break;
	case SERVICE_READ_EOF:
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Service done.");
	  break;
	case TRANSPORT_READ_PUSH:
	  transport_send_packet(&self->super, 0, NULL);
	  /* Fall through */
	case TRANSPORT_READ_PENDING:
	  return OOP_CONTINUE;

	case SERVICE_READ_COMPLETE:
	  if (!length)
	    transport_disconnect(&self->super, SSH_DISCONNECT_BY_APPLICATION,
				 "Received empty packet from service layer.");
	  else
	    {
	      /* FIXME: This is unnecessary allocation and copying. */
	      transport_send_packet(&self->super, 0,
				    ssh_format("%ls", length, packet));
	      if (packet[0] == SSH_MSG_DISCONNECT)
		transport_close(&self->super, 1);
	    }
	}
    }
  return OOP_CONTINUE;
}

static void
lshd_service_start_read(struct lshd_connection *self)
{
  if (!self->service_read_active)
    {
      oop_source *source = self->super.ctx->oop;
      self->service_read_active = 1;
      source->on_fd(source, self->service_fd, OOP_READ, oop_read_service, self);
    }
}

static void
lshd_service_stop_read(struct lshd_connection *self)
{
  if (self->service_read_active)
    {
      oop_source *source = self->super.ctx->oop;

      self->service_read_active = 0;
      source->cancel_fd(source, self->service_fd, OOP_READ);
    }
}

static void *
oop_write_service(oop_source *source UNUSED,
		  int fd, oop_event event, void *state)
{
  CAST(lshd_connection, self, (struct lsh_object *) state);
  enum ssh_write_status status;

  assert(fd == self->service_fd);
  assert(event == OOP_WRITE);

  status = ssh_write_flush(self->service_writer, self->service_fd);
  switch(status)
    {
    case SSH_WRITE_IO_ERROR:
      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Connection to service layer failed.");
      break;
    case SSH_WRITE_OVERFLOW:
      werror("Overflow from ssh_write_flush! Should not happen.\n");
      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Service layer not responsive.");
      break;
    case SSH_WRITE_PENDING:
      /* Do nothing. */
      break;

    case SSH_WRITE_COMPLETE:
      lshd_service_stop_write(self);
      break;
    }
  return OOP_CONTINUE;
}

static void
lshd_service_start_write(struct lshd_connection *self)
{
  if (!self->service_write_active)
    {
      oop_source *source = self->super.ctx->oop;

      self->service_write_active = 1;
      source->on_fd(source, self->service_fd, OOP_WRITE, oop_write_service, self);
    }
}

static void
lshd_service_stop_write(struct lshd_connection *self)
{
  if (self->service_write_active)
    {
      oop_source *source = self->super.ctx->oop;

      self->service_write_active = 0;
      source->cancel_fd(source, self->service_fd, OOP_WRITE);
      transport_start_read(&self->super);
    }
}

/* Handles all packets to be sent to the service layer. */
static int
lshd_service_handler(struct lshd_connection *self,
		     uint32_t seqno, uint32_t length, const uint8_t *packet)
{
  enum ssh_write_status status;
  uint8_t header[8];

  if (ssh_write_available(self->service_writer) < length + 8)
    return 0;

  WRITE_UINT32(header, seqno);
  WRITE_UINT32(header + 4, length);

  status = ssh_write_data(self->service_writer,
			  self->service_fd, 0,
			  sizeof(header), header);
  if (status >= 0)
    status = ssh_write_data(self->service_writer,
			    self->service_fd, SSH_WRITE_FLAG_PUSH,
			    length, packet);

  switch (status)
    {
    case SSH_WRITE_IO_ERROR:
      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Connection to service layer failed.");
      break;
    case SSH_WRITE_OVERFLOW:
      werror("Overflow when sending packet to service layer! Should not happen.\n");
      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Service layer not responsive.");
      break;
    case SSH_WRITE_PENDING:
      lshd_service_start_write(self);
      break;
    case SSH_WRITE_COMPLETE:
      transport_start_read(&self->super);
      break;
    }
  return 1;
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
lshd_service_request_handler(struct lshd_connection *self,
			     uint32_t length, const uint8_t *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  const uint8_t *name;
  uint32_t name_length;

  assert(self->service_state == SERVICE_ENABLED);

  simple_buffer_init(&buffer, length, packet);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_string(&buffer, &name_length, &name)
      && parse_eod(&buffer))
    {
      CAST(configuration, config, self->super.ctx);
      const char *program = lookup_service(config->services,
					   name_length, name);

      if (program)
	{
	  int pipe[2];
	  pid_t child;

	  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0)
	    {
	      werror("lshd_service_request_handler: socketpair failed: %e\n",
		     errno);
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				   "Service could not be started");
	      return;
	    }
	  child = fork();
	  if (child < 0)
	    {
	      werror("lshd_service_request_handler: fork failed: %e\n",
		     errno);
	      close(pipe[0]);
	      close(pipe[1]);
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				   "Service could not be started");
	      return;
	    }
	  if (child)
	    {
	      /* Parent process */
	      close(pipe[1]);
	      io_set_nonblocking(pipe[0]);
	      self->service_fd = pipe[0];
	      self->service_state = SERVICE_STARTED;

	      self->service_reader = make_service_read_state();
	      lshd_service_start_read(self);

	      self->service_writer
		= make_ssh_write_state(SERVICE_WRITE_BUFFER_SIZE,
				       SERVICE_WRITE_THRESHOLD);

	      transport_send_packet(&self->super, SSH_WRITE_FLAG_PUSH,
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

	      hex = ssh_format("%lxS", self->super.session_id);

	      /* FIXME: Pass sufficient information so that
		 $SSH_CLIENT can be set properly. */
	      execl(program, program, "--session-id", lsh_string_data(hex), NULL);

	      werror("lshd_service_request_handler: exec failed: %e\n", errno);
	      _exit(EXIT_FAILURE);
	    }
	}
      else
	transport_disconnect(&self->super,
			     SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
			      "Service not available");
    }
  else
    transport_protocol_error(&self->super, "Invalid SERVICE_REQUEST");
}

/* Handles decrypted packets above the ssh transport layer. */
static int
lshd_packet_handler(struct transport_connection *connection,
		    uint32_t seqno, uint32_t length, const uint8_t *packet)
{
  CAST(lshd_connection, self, connection);

  uint8_t msg;

  werror("Received packet: %xs\n", length, packet);
  assert(length > 0);

  msg = packet[0];

  if (msg == SSH_MSG_SERVICE_REQUEST)
    {
      if (self->service_state != SERVICE_ENABLED)
	transport_disconnect(connection,
			     SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
			     "Unexpected service request");
      else
	lshd_service_request_handler(self, length, packet);
    }
  else if (msg >= SSH_FIRST_USERAUTH_GENERIC
	   && self->service_state == SERVICE_STARTED)
    return lshd_service_handler(self, seqno, length, packet);
  else
    transport_send_packet(connection, SSH_WRITE_FLAG_PUSH,
			  format_unimplemented(seqno));

  return 1;
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
  oop_source *source = self->config->super.oop;
  if (self->super.alive)
    {
      self->super.alive = 0;
      source->cancel_fd(source, self->fd, OOP_WRITE);
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
  gc_global(&connection->super.super);

  transport_handshake(&connection->super, make_string("SSH-2.0-lshd-ng"),
		      lshd_line_handler);

  return OOP_CONTINUE;
}

static struct resource_list *
open_ports(struct configuration *config, int port_number)
{
  struct resource_list *ports = make_resource_list();
  struct sockaddr_in sin;
  struct lshd_port *port;
  oop_source *source;
  int yes = 1;
  int s;

  source = config->super.oop;

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

  source->on_fd(source, s, OOP_READ, lshd_port_accept, port);

  gc_global(&ports->super);
  return ports;
}

static struct configuration *
make_configuration(const char *hostkey, oop_source *source)
{
  NEW(configuration, self);
  static const char *services[] =
    { "ssh-userauth", "lshd-userauth", NULL };

  self->super.is_server = 1;

  self->super.random = make_system_random();

  if (!self->super.random)
    {
      werror("No randomness generator available.\n");
      exit(EXIT_FAILURE);
    }

  self->super.algorithms = all_symmetric_algorithms();
  self->super.oop = source;

  self->keys = make_alist(0, -1);
  if (!read_host_key(hostkey,
		     all_signature_algorithms(self->super.random),
		     self->keys))
    werror("No host key.\n");

  ALIST_SET(self->super.algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_server_dh_exchange(make_dh_group14(&crypto_sha1_algorithm),
				     self->keys)->super);

  self->super.kexinit
    = make_simple_kexinit(
      make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
      filter_algorithms(self->keys, default_hostkey_algorithms()),
      default_crypto_algorithms(self->super.algorithms),
      default_mac_algorithms(self->super.algorithms),
      default_compression_algorithms(self->super.algorithms),
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
  oop_source *source;
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  source = io_init();

  werror("Listening on port 4711\n");
  if (!open_ports(make_configuration("testsuite/key-1.private", source),
		  4711))
    return EXIT_FAILURE;

  /* Ignore status from child processes */
  signal(SIGCHLD, SIG_IGN);

  io_run();

  return EXIT_SUCCESS;
}
