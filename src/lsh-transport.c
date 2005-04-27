/* lsh-transport.c
 *
 * Client program responsible for the transport protocol and
 * user authnetication.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2005, Niels Möller
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
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "algorithms.h"
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "publickey_crypto.h"
#include "randomness.h"
#include "resource.h"
#include "service.h"
#include "ssh.h"
#include "ssh_write.h"
#include "transport.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh-transport.c.x"

static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno, uint32_t length, const uint8_t *packet);

static void
lsh_transport_service_start_read(struct lsh_transport_connection *self);

static void
lsh_transport_service_stop_read(struct lsh_transport_connection *self);

static void
lsh_transport_service_start_write(struct lsh_transport_connection *self);

static void
lsh_transport_service_stop_write(struct lsh_transport_connection *self);

static struct lookup_verifier *
make_lsh_lookup_verifier(struct lsh_transport_config *config);

/* GABA:
   (class
     (name lsh_transport_config)
     (super transport_context)
     (vars
       (tty object interact)

       (sloppy . int)
       (capture . "const char *")
       (capture_file object abstract_write)
       (known_hosts . "const char *")
       
       (home . "const char *")       
       (port . "const char *")
       (target . "const char *")

       (local_user . "char *")
       (user . "char *")
       (identity . "char *")

       (service . "const char *")))
*/

static struct lsh_transport_config *
make_lsh_transport_config(oop_source *oop)
{
  NEW(lsh_transport_config, self);
  self->super.is_server = 0;
  self->super.oop = oop;

  self->home = getenv(ENV_HOME);
  if (!self->home)
    {
      werror("No home directory. Please set HOME in the environment.");
      return NULL;
    }
  
  self->super.random = make_user_random(self->home);
  if (!self->super.random)
    {
      werror("No randomness generator available.\n");
      return NULL;
    }
  
  self->tty = make_unix_interact();

  self->super.algorithms = all_symmetric_algorithms();

  ALIST_SET(self->super.algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_client_dh_exchange(make_dh_group14(&crypto_sha1_algorithm),
				     make_lsh_lookup_verifier(self))->super);
  self->super.kexinit
    = make_simple_kexinit(make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
			  default_hostkey_algorithms(),
			  default_crypto_algorithms(self->super.algorithms),
			  default_mac_algorithms(self->super.algorithms),
			  default_compression_algorithms(self->super.algorithms),
			  make_int_list(0, -1));
  self->sloppy = 0;
  self->capture = 0;
  self->capture_file = NULL;
  self->known_hosts = NULL;

  self->port = "22";
  self->target = NULL;

  USER_NAME_FROM_ENV(self->user);
  self->local_user = self->user;
  self->identity = NULL;

  self->service = "ssh-connection";
  
  return self;
}

/* GABA:
   (class
     (name lsh_transport_connection)
     (super transport_connection)
     (vars
       (service_reader object service_read_state)
       (service_read_active . int)
       (service_writer object ssh_write_state)
       (service_write_active . int)))     
*/

static void
kill_lsh_transport_connection(struct resource *s UNUSED)
{
  exit(EXIT_SUCCESS);
}

static int
lsh_transport_event_handler(struct transport_connection *connection,
			    enum transport_event event)
{
  CAST(lsh_transport_connection, self, connection);
  switch (event)
    {
    case TRANSPORT_EVENT_START_APPLICATION:
      lsh_transport_service_start_read(self);
      break;
    case TRANSPORT_EVENT_STOP_APPLICATION:
      lsh_transport_service_stop_read(self);
      break;
    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      connection->packet_handler = lsh_transport_packet_handler;
      break;
    case TRANSPORT_EVENT_CLOSE:
      /* FIXME: Should allow service buffer to drain. */
      break;
    case TRANSPORT_EVENT_PUSH:
      {
	enum ssh_write_status status;

	status = ssh_write_flush(self->service_writer, STDOUT_FILENO);

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
	    lsh_transport_service_start_write(self);
      
	  case SSH_WRITE_COMPLETE:
	    lsh_transport_service_stop_write(self);
	    break;
	  }
	}
    }
  return 0;
}

static struct lsh_transport_connection *
make_lsh_transport_connection(struct lsh_transport_config *config, int fd)
{
  NEW(lsh_transport_connection, self);
  init_transport_connection(&self->super, kill_lsh_transport_connection,
			    &config->super, fd, fd,
			    lsh_transport_event_handler);
  self->service_reader = make_service_read_state();
  self->service_read_active = 0;
  self->service_writer = make_ssh_write_state(3 * SSH_MAX_PACKET, 1000);
  self->service_write_active = 0;

  return self;
}


static void
lsh_transport_line_handler(struct transport_connection *connection,
			   uint32_t length, const uint8_t *line)
{
  if (length < 4 || 0 != memcmp(line, "SSH-", 4))
    {
      /* A banner line */
      werror("%ps\n", length, line);
      return;
    }
  verbose("Server version string: %ps\n", length, line);

  /* Line must start with "SSH-2.0-". */
  if (length < 8 || 0 != memcmp(line, "SSH-2.0-", 4))
    {
      transport_disconnect(connection, 0, "Bad version string.");
      return;
    }
  
  connection->kex.version[1] = ssh_format("%ls", length, line);
  connection->line_handler = NULL;
}

/* Communication with service layer */

static void *
oop_read_service(oop_source *source UNUSED,
		 int fd UNUSED, oop_event event UNUSED, void *state UNUSED)
{
  return OOP_HALT;
}

static void
lsh_transport_service_start_read(struct lsh_transport_connection *self UNUSED)
{
}

static void
lsh_transport_service_stop_read(struct lsh_transport_connection *self UNUSED)
{
}

static void *
oop_write_service(oop_source *source UNUSED,
		  int fd UNUSED, oop_event event UNUSED, void *state UNUSED)
{
  return OOP_HALT;
}

static void
lsh_transport_service_start_write(struct lsh_transport_connection *self UNUSED)
{
}

static void
lsh_transport_service_stop_write(struct lsh_transport_connection *self UNUSED)
{
}

/* Handles decrypted packets. The various handler functions called
   from here should *not* free the packet. FIXME: Better to change
   this? */
static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno UNUSED, uint32_t length, const uint8_t *packet)
{
  CAST(lsh_transport_connection, self, connection);
  
  uint8_t msg;
  
  werror("Received packet: %xs\n", length, packet);
  assert(length > 0);

  msg = packet[0];
  /* XXX */

  return 1;
}

static int
lsh_connect(struct lsh_transport_config *config)
{
  struct lsh_transport_connection *connection;

  struct addrinfo hints;
  struct addrinfo *list;
  struct addrinfo *p;
  int err;
  int s = -1;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  err = getaddrinfo(config->target, config->port, &hints, &list);
  if (err)
    {
      werror("Could not resolv address `%z', port %z: %z\n",
	     config->target, config->port, gai_strerror(err));
      return 0;
    }

  for (p = list; p; p = p->ai_next)
    {
      s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (s < 0)
	continue;

      if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
	break;

      if (p->ai_next)
	werror("Connection failed, trying next address.\n");
      else
	werror("Connection failed.\n");
      close(s);
      s = -1;
    }
  
  freeaddrinfo(list);

  if (s < 0)
    return 0;
  
  /* We keep the socket in blocking mode */
  connection = make_lsh_transport_connection(config, s);
  gc_global(&connection->super.super);

  transport_handshake(&connection->super,
		      make_string("SSH-2.0-lsh-transport"),
		      lsh_transport_line_handler);

  return 1;
}

/* Maps a host key to a (trusted) verifier object. */

/* GABA:
   (class
     (name lsh_transport_lookup_verifier)
     (super lookup_verifier)
     (vars
       (config object lsh_transport_config)))
*/

static struct verifier *
lsh_transport_lookup_verifier(struct lookup_verifier *s UNUSED,
			      int hostkey_algorithm UNUSED,
			      uint32_t key_length UNUSED, const uint8_t *key UNUSED)
{
  return NULL;
}

static struct lookup_verifier *
make_lsh_lookup_verifier(struct lsh_transport_config *config)
{
  NEW(lsh_transport_lookup_verifier, self);
  self->super.lookup = lsh_transport_lookup_verifier;
  self->config = config;
  
  return &self->super;
}


/* Option parsing */

const char *argp_program_version
= "lsh-transport (lsh-" VERSION "), secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

/* Transport options */
#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204
#define OPT_HOST_DB 0x205

/* Userauth options */
#define OPT_USERAUTH 0x210
#define OPT_PUBLICKEY 0x211

/* FIXME: Enable/disable password, kbdinteract, etc */

/* Service options */
#define OPT_SERVICE 0x220

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  /* Connection */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },

  /* Host authentication */
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/host-acls", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new hostkey is received, append an ACL expressing trust in the key. "
    "In sloppy mode, the default is ~/.lsh/captured_keys.", 0 },
  
  /* User authentication */
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "service" , OPT_SERVICE, "Name", 0, "Service to request. Default is `ssh-connection'.", 0},
  
  { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_transport_config, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;

    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;

    case ARGP_KEY_ARG:
      if (!state->arg_num)
	self->target = arg;
      
      else
	return ARGP_ERR_UNKNOWN;

      break;
      
    case ARGP_KEY_END:
      /* FIXME: Open capture file if appropriate */
      break;
      
    case 'p':
      self->port = arg;
      break;

    case OPT_HOST_DB:
      self->known_hosts = arg;
      break;
      
    case OPT_SLOPPY:
      self->sloppy = 1;
      break;

    case OPT_STRICT:
      self->sloppy = 0;
      break;

    case OPT_CAPTURE:
      self->capture = arg;
      break;

    case 'i':
      self->identity = arg;
      break;

    case OPT_SERVICE:
      self->service = arg;
      break;
    }
  return 0;
}

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ main_options, main_argp_parser,
  "host",
  "Creates a secure shell connection to a remote host\v"
  "Uses secure shell transport and userauth protocols to "
  "talk to the remote host. On success, reads cleartext"
  "ssh messages on stdin writes cleartext messages to stdout.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{
  struct lsh_transport_config *config;
  struct oop_source *source = io_init();
  
  config = make_lsh_transport_config(source);
  if (!config)
    return EXIT_FAILURE;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, config);

  if (!lsh_connect(config))
    return EXIT_FAILURE;

  io_run();
  io_final();

  return EXIT_SUCCESS;
}
