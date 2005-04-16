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
#include "randomness.h"
#include "resource.h"
#include "ssh.h"
#include "ssh_write.h"
#include "transport_read.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh-transport.c.x"

static struct lsh_transport_read_state *
make_lsh_transport_read_state(struct lsh_transport_connection *connection);

static void
connection_disconnect(struct lsh_transport_connection *connection,
		      int reason, const uint8_t *msg);

static void
lsh_transport_handle_ssh_packet(struct transport_read_state *s, struct lsh_string *packet);

static oop_source *global_oop_source;

/* GABA:
   (class
     (name lsh_transport_config)
     (vars
       (random object randomness)
       (algorithms object alist)
       (tty object interact)

       (kexinit object make_kexinit)
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
make_lsh_transport_config(void)
{
  NEW(lsh_transport_config, self);

  self->home = getenv(ENV_HOME);
  if (!self->home)
    {
      werror("No home directory. Please set HOME in the environment.");
      return NULL;
    }
  
  self->random = make_user_random(self->home);
  if (!self->random)
    {
      werror("No randomness generator available.\n");
      return NULL;
    }
  
  self->tty = make_unix_interact();

  self->algorithms = all_symmetric_algorithms();
#if 0
  ALIST_SET(self->algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_lsh_transport_dh_handler(make_dh14(self->random))->super);
#endif
  self->kexinit = make_simple_kexinit(self->random,
				      make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
				      default_hostkey_algorithms(),
				      default_crypto_algorithms(self->algorithms),
				      default_mac_algorithms(self->algorithms),
				      default_compression_algorithms(self->algorithms),
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
     (super resource)
     (vars
       (config object lsh_transport_config)
       ; Key exchange 
       (kex struct kexinit_state)
       
       (session_id string)

       ; Connection fd
       (fd . int)

       ; Receiving encrypted packets
       (reader object lsh_transport_read_state)

       ; Sending encrypted packets
       (writer object ssh_write_state)
       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)
       (send_seqno . uint32_t)))
*/

static void
kill_lsh_transport_connection(struct resource *s)
{
  CAST(lsh_transport_connection, self, s);
  if (self->super.alive)
    {
      close(self->fd);
      exit(EXIT_FAILURE);
    }
}

static struct lsh_transport_connection *
make_lsh_transport_connection(struct lsh_transport_config *config, int fd)
{
  NEW(lsh_transport_connection, self);
  init_resource(&self->super, kill_lsh_transport_connection);

  self->config = config;
  
  init_kexinit_state(&self->kex);
  self->session_id = NULL;

  self->fd = fd;
  self->reader = make_lsh_transport_read_state(self);

  self->writer = make_ssh_write_state();
  self->send_mac = NULL;
  self->send_crypto = NULL;
  self->send_compress = NULL;
  self->send_seqno = 0;

  return self;
}

/* FIXME: Duplicates code in lshd.c. We need a shared transport object
   responsible for encrypted input, output and some of the keyexchange
   logic. */
static void
connection_write_data(struct lsh_transport_connection *connection,
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
		     global_oop_source, connection->fd, data) < 0)
    {
      werror("write failed: %e\n", errno);
      connection_disconnect(connection, 0, NULL);
    }
}

static void
connection_write_packet(struct lsh_transport_connection *connection,
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

static void
connection_disconnect(struct lsh_transport_connection *connection,
		      int reason, const uint8_t *msg)
{
  if (reason)
    connection_write_packet(connection, format_disconnect(reason, msg, ""));

  KILL_RESOURCE(&connection->super);
};

/* GABA:
   (class
     (name lsh_transport_read_state)
     (super transport_read_state)
     (vars
       (connection object lsh_transport_connection)))
*/

static void
lsh_transport_read_error(struct ssh_read_state *s, int error)
{
  CAST(lsh_transport_read_state, self, s);
  werror("Read failed: %e\n", error);
  KILL(&self->connection->super);
}

static void
lsh_transport_protocol_error(struct transport_read_state *s, int reason, const char *msg)
{
  CAST(lsh_transport_read_state, self, s);
  connection_disconnect(self->connection, reason, msg);
}

static struct lsh_transport_read_state *
make_lsh_transport_read_state(struct lsh_transport_connection *connection)
{
  NEW(lsh_transport_read_state, self);
  init_transport_read_state(&self->super, SSH_MAX_PACKET,
			    lsh_transport_read_error, lsh_transport_protocol_error);

  self->connection = connection;
  return self;
}

static void
lsh_transport_handle_line(struct ssh_read_state *s, struct lsh_string *line)
{
  CAST(lsh_transport_read_state, self, s);
  struct lsh_transport_connection *connection = self->connection;
  const uint8_t *data;
  uint32_t length;

  length = lsh_string_length(line);
  data = lsh_string_data(line);
  if (length < 4 || 0 != memcmp(data, "SSH-", 4))
    {
      /* A banner line */
      werror("%pfS\n", line);
      /* Prepare for next line */
      ssh_read_line(&connection->reader->super.super, 256,
		    global_oop_source, connection->fd,
		    lsh_transport_handle_line);           
    }
  verbose("Server version string: %pS\n", line);


  /* Line must start with "SSH-2.0-" or "SSH-1.99". FIXME: 1.99 not implemented */
  if (length < 8 || 0 != memcmp(data, "SSH-2.0-", 4))
    {
      connection_disconnect(self->connection, 0, NULL);
      return;
    }

  self->connection->kex.version[1] = line;

  transport_read_packet(&self->super,
			global_oop_source, self->connection->fd,
			lsh_transport_handle_ssh_packet);
}

/* Handles decrypted packets. The various handler functions called
   from here should *not* free the packet. FIXME: Better to change
   this? */
static void
lsh_transport_handle_ssh_packet(struct transport_read_state *s, struct lsh_string *packet)
{
  CAST(lsh_transport_read_state, self, s);
  struct lsh_transport_connection *connection = self->connection;
  
  werror("Received packet: %xS\n", packet);
  lsh_string_free(packet);
}

static void
lsh_transport_send_kexinit(struct lsh_transport_connection *connection)
{
  struct lsh_string *s;
  struct kexinit *kex
    = connection->kex.kexinit[0]
    = MAKE_KEXINIT(connection->config->kexinit);
  
  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.state == KEX_STATE_INIT);

  /* FIXME: Deal with timeout */
  
  s = format_kexinit(kex);
  connection->kex.literal_kexinit[0] = lsh_string_dup(s); 
  connection_write_packet(connection, s);

  if (kex->first_kex_packet)
    fatal("Not implemented\n");
}

static void
lsh_transport_handshake(struct lsh_transport_connection *connection)
{
  connection->kex.version[0] = make_string("SSH-2.0-lsh-transport");

  ssh_read_line(&connection->reader->super.super, 256,
		global_oop_source, connection->fd,
		lsh_transport_handle_line);
  ssh_read_start(&connection->reader->super.super,
		 global_oop_source, connection->fd);

  connection_write_data(connection,
			ssh_format("%lS\r\n", connection->kex.version[0]));
  lsh_transport_send_kexinit(connection);
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
  gc_global(&connection->super);

  lsh_transport_handshake(connection);

  return 1;
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

  config = make_lsh_transport_config();
  if (!config)
    return EXIT_FAILURE;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, config);

  global_oop_source = io_init();

  if (!lsh_connect(config))
    return EXIT_FAILURE;

  io_run();
  io_final();

  return EXIT_SUCCESS;
}
