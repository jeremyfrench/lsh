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
#include <locale.h>
#include <string.h>

#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <oop.h>

#include "nettle/macros.h"

#include "algorithms.h"
#include "charset.h"
#include "crypto.h"
#include "environ.h"
#include "daemon.h"
#include "format.h"
#include "io.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "parse.h"
#include "randomness.h"
#include "server.h"
#include "service.h"
#include "spki.h"
#include "ssh.h"
#include "transport_forward.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd.c.x"

#define SERVICE_WRITE_THRESHOLD 1000
#define SERVICE_WRITE_BUFFER_SIZE (3 * SSH_MAX_PACKET)

/* Information shared by several connections */
/* GABA:
   (class
     (name lshd_context)
     (super transport_context)
     (vars
       (service_config object service_config)

       (keys object alist)))
*/

/* Connection */
static void
kill_lshd_connection(struct resource *s)
{
  CAST(transport_forward, self, s);
  if (self->super.super.alive)
    {
      self->super.super.alive = 0;
      transport_forward_kill(self);
    }
}

static int
lshd_packet_handler(struct transport_connection *connection,
		    uint32_t seqno, uint32_t length, const uint8_t *packet);

/* Used only until the service is started. */
static void
lshd_event_handler(struct transport_connection *connection,
		   enum transport_event event)
{
  switch (event)
    {
    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      connection->packet_handler = lshd_packet_handler;
      break;

    case TRANSPORT_EVENT_START_APPLICATION:
    case TRANSPORT_EVENT_STOP_APPLICATION:
    case TRANSPORT_EVENT_CLOSE:
    case TRANSPORT_EVENT_PUSH:
      /* Do nothing */
      break;
    }
}

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

static struct lsh_string *
format_service_accept(uint32_t name_length, const uint8_t *name)
{
  return ssh_format("%c%s", SSH_MSG_SERVICE_ACCEPT, name_length, name);
};

static void
lshd_service_request_handler(struct transport_forward *self,
			     uint32_t length, const uint8_t *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  const uint8_t *name;
  uint32_t name_length;

  simple_buffer_init(&buffer, length, packet);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_string(&buffer, &name_length, &name)
      && parse_eod(&buffer))
    {
      CAST(lshd_context, ctx, self->super.ctx);
      const struct service_entry *service
	= service_config_lookup(ctx->service_config,
				name_length, name);
      
      if (service)
	{
	  int pipe[2];
	  pid_t child;

	  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0)
	    {
	      werror("lshd_service_request_handler: socketpair failed: %e.\n",
		     errno);
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				   "Service could not be started");
	      return;
	    }

	  child = fork();
	  if (child < 0)
	    {
	      werror("lshd_service_request_handler: fork failed: %e.\n",
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

	      transport_send_packet(&self->super, TRANSPORT_WRITE_FLAG_PUSH,
				    format_service_accept(name_length, name));

	      /* Setup forwarding. Replaces event_handler and packet_handler. */
	      transport_forward_setup(self, pipe[0], pipe[0]);
	    }
	  else
	    {
	      /* Child process */
	      struct arglist args;
	      const char *program;
	      unsigned i;

	      close(pipe[0]);
	      dup2(pipe[1], STDIN_FILENO);
	      dup2(pipe[1], STDOUT_FILENO);
	      close(pipe[1]);

	      /* FIXME: Pass sufficient information so that
		 $SSH_CLIENT can be set properly. */
	      arglist_init (&args);

	      program = service->args.argv[0];
	      arglist_push (&args, program);

	      /* If not absolute, interpret it relative to
		 libexecdir. */
	      if (program[0] != '/')
		program = lsh_get_cstring(ssh_format("%lz/%lz",
						     ctx->service_config->libexec_dir,
						     program));
	      
	      for (i = 1; i < service->args.argc; i++)
		{
		  const char *arg = service->args.argv[i];
		  if (arg[0] == '$')
		    {
		      if (!strcmp(arg+1, "(session_id)"))
			arg = lsh_get_cstring(ssh_format("%lxS",
							 self->super.session_id));
		    }
		  arglist_push (&args, arg);
		}
	      debug("exec of service %s, program %z. Argument list:\n",
		    name_length, name, program);
	      for (i = 0; i < args.argc; i++)
		debug("  %z\n", args.argv[i]);

	      execv(program, (char **) args.argv);

	      werror("lshd_service_request_handler: exec of %z failed: %e.\n",
		     args.argv[0], errno);
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

/* Handles decrypted packets above the ssh transport layer. Replaced
   after the service exchange is complete. */
static int
lshd_packet_handler(struct transport_connection *connection,
		    uint32_t seqno, uint32_t length, const uint8_t *packet)
{
  CAST(transport_forward, self, connection);

  uint8_t msg;

  assert(length > 0);
  msg = packet[0];

  trace("lshd_packet_handler: %T (%i) message, length %i\n",
	msg, msg, length);

  /* Never dump userauth packets. */
  if (msg < SSH_FIRST_USERAUTH_GENERIC
      || msg >= SSH_FIRST_CONNECTION_GENERIC) 
    debug("lshd_packet_handler: contents: %xs\n", length, packet);

  if (msg == SSH_MSG_SERVICE_REQUEST)
    {
      lshd_service_request_handler(self, length, packet);
    }
  else
    {
      /* FIXME: If for example userauth packets are received before
	 the corresponding service is started, we reply with
	 UNIMPLEMENTED, not DISCONNECT. */
	 
      transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH,
			    format_unimplemented(seqno));
    }
  
  return 1;
}

/* GABA:
   (class
     (name lshd_port)
     (super io_listen_port)
     (vars
       (ctx object lshd_context)))
*/

static void
lshd_port_accept(struct io_listen_port *s,
		 int fd,
		 socklen_t addr_len, const struct sockaddr *addr)
{
  CAST(lshd_port, self, s);
  struct transport_forward *connection;

  /* FIXME: Use the provided address, for logging or tcpwrappers. */
  connection = make_transport_forward(kill_lshd_connection,
				      &self->ctx->super, fd, fd,
				      lshd_event_handler);
  gc_global(&connection->super.super);

  transport_handshake(&connection->super, make_string(SERVER_VERSION_LINE),
		      lshd_line_handler);
}

static struct resource *
make_lshd_port(struct lshd_context *ctx, socklen_t addr_len, struct sockaddr *addr)
{
  int fd = io_bind_sockaddr(addr, addr_len);

  if (fd < 0)
    {
      werror("socket failed: %e.\n", errno);
      return NULL;
    }
  else
    {
      NEW(lshd_port, self);
      
      init_io_listen_port(&self->super, fd, lshd_port_accept);
      self->ctx = ctx;

      if (!io_listen(&self->super))
	{
	  werror("listen failed: %e.\n", errno);
	  KILL_RESOURCE(&self->super.super.super);
	  return NULL;
	}

      return &self->super.super.super;
    }
}

static struct lshd_context *
make_lshd_context(void)
{
  NEW(lshd_context, self);

  init_transport_context (&self->super, 1);
  self->service_config = make_service_config ();

  self->keys = make_alist(0, -1);

  return self;
}


/* GABA:
   (class
     (name pid_file_resource)
     (super resource)
     (vars
       (file string)))
*/

static void
do_kill_pid_file(struct resource *s)
{
  CAST(pid_file_resource, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;
      if (unlink(lsh_get_cstring(self->file)) < 0)
	werror("Unlinking pidfile failed: %e.\n", errno);
    }
}

/* Consumes file name */
static struct resource *
make_pid_file_resource(struct lsh_string *file)
{
  NEW(pid_file_resource, self);
  init_resource(&self->super, do_kill_pid_file);
  self->file = file;

  return &self->super;
}

/* GABA:
   (class
     (name sighup_close_callback)
     (super lsh_callback)
     (vars
       (resource object resource)))
*/

static void
do_sighup_close_callback(struct lsh_callback *s)
{
  CAST(sighup_close_callback, self, s);
  
  werror("SIGHUP received.\n");
  KILL_RESOURCE(self->resource);
}

static struct lsh_callback *
make_sighup_close_callback(struct resource *resource)
{
  NEW(sighup_close_callback, self);
  self->super.f = do_sighup_close_callback;
  self->resource = resource;

  return &self->super;
}

/* Option and config file processing */

/* GABA:
   (class
     (name lshd_interface)
     (vars
       (name const string)
       (port const string)))
*/
   
/* GABA:
   (class
     (name lshd_config)
     (super server_config)
     (vars
       ; Command line options
       (algorithms object algorithms_options)

       (ctx object lshd_context)

       (ports struct string_queue)
       (ports_override_config_file . int)
       (interfaces struct object_queue)
       (interfaces_override_config_file . int)

       (hostkey string)

       (daemonic . int)
       (daemon_flags . "enum daemon_flags")
       ;; (background . int)
       (corefile . int)
       (pid_file string)
       ; -1 means use pid file iff we are in daemonic mode
       (use_pid_file . int)))
*/

static const struct config_parser
lshd_config_parser;

static struct lshd_config *
make_lshd_config(struct lshd_context *ctx)
{
  NEW(lshd_config, self);
  init_server_config(&self->super, &lshd_config_parser,
		     FILE_LSHD_CONF, ENV_LSHD_CONF);

  self->algorithms = make_algorithms_options(all_symmetric_algorithms());

  self->ctx = ctx;

  /* Default behaviour is to lookup the "ssh" service, and fall back
   * to port 22 if that fails. */
  string_queue_init(&self->ports);
  self->ports_override_config_file = 0;
  object_queue_init(&self->interfaces);
  self->interfaces_override_config_file = 0;

  self->hostkey = NULL;
  self->daemonic = 0;
  self->daemon_flags = 0;

  self->pid_file = NULL;
  self->use_pid_file = -1;
  self->corefile = -1;
  
  return self;
}

/* Look up a port using getaddrinfo, and bind one or more sockets. */
static unsigned
open_port (struct lshd_context *ctx, struct resource_list *resources,
	   const struct lsh_string *interface, const struct lsh_string *port)
{
#if HAVE_GETADDRINFO
  struct addrinfo hints;
  struct addrinfo *list;
  struct addrinfo *p;
  int err;

  const char *node;
  unsigned done = 0;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  node = interface ? lsh_get_cstring(interface) : NULL;

  if (node && !node[0])
    node = NULL;

  debug("open_port: node = %z, port = %S\n",
	node ? node : "ANY", port);

  /* FIXME: Also use AI_ADDRCONFIG? */
  hints.ai_flags = AI_PASSIVE;

  err = getaddrinfo(node, lsh_get_cstring(port), &hints, &list);
  if (err)
    werror ("getaddrinfo failed: %z\n", gai_strerror(err));
  else
    {
      for (p = list; p; p = p->ai_next)
	{
	  if (p->ai_family == AF_INET || p->ai_family == AF_INET6)
	    {
	      struct resource *port = 
		make_lshd_port (ctx, p->ai_addrlen, p->ai_addr);
	      if (port)
		{
		  remember_resource(resources, port);
		  done++;
		}
	    }
	}
      freeaddrinfo(list);
    }
  return done;
#else /* !HAVE_GETADDRINFO */
#error getaddrinfo currently required */
#endif /* !HAVE_GETADDRINFO */
}

/* Bind all appropriate ports for a given interface. */
static unsigned
open_interface(struct lshd_context *ctx, struct resource_list *resources,
	       struct lshd_interface *interface, struct string_queue *ports)
{
  debug("open_interface: name = %z, port = %z\n",
	interface && interface->name ? lsh_get_cstring(interface->name) : "ANY",
	interface && interface->port ? lsh_get_cstring(interface->port) : "DEFAULT");

  if (interface && interface->port)
    return open_port(ctx, resources, interface->name, interface->port);
  else
    {
      const struct lsh_string *name = interface ? interface->name : NULL;
      unsigned done = 0;

      FOR_STRING_QUEUE(ports, port)
	done += open_port(ctx, resources, name, port);

      return done;
    }
}

/* Open all configured ports on all interfaces. */
static unsigned
open_all_ports(struct lshd_context *ctx, struct resource_list *resources,
	       struct object_queue *interfaces, struct string_queue *ports)
{
  if (object_queue_is_empty (interfaces))
    return open_interface(ctx, resources, NULL, ports);
  else
    {
      unsigned done = 0;

      FOR_OBJECT_QUEUE(interfaces, o)
	{
	  CAST(lshd_interface, interface, o);
	  done += open_interface(ctx, resources, interface, ports);
	}
      return done;
    }
}

/* Read server's private key */

static void
add_key(struct alist *keys,
        struct keypair *key)
{
  if (ALIST_GET(keys, key->type))
    werror("Multiple host keys for algorithm %a\n", key->type);
  ALIST_SET(keys, key->type, &key->super);
}

static int
read_host_key(const char *file,
              struct alist *signature_algorithms,
              struct alist *keys)
{
  int fd = open(file, O_RDONLY);
  struct lsh_string *contents;
  struct signer *s;
  struct verifier *v;
  
  int algorithm_name;

  if (fd < 0)
    {
      werror("Failed to open `%z' for reading: %e.\n", file, errno);
      return 0;
    }
  
  contents = io_read_file_raw(fd, 5000);
  if (!contents)
    {
      werror("Failed to read host key file `%z': %e.\n", file, errno);
      close(fd);
      return 0;
    }
  close(fd);

  s = spki_make_signer(signature_algorithms,
		       contents,
		       &algorithm_name);
  lsh_string_free(contents);
  
  if (!s)
    {
      werror("Invalid host key\n");
      return 0;
    }

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  switch (algorithm_name)
    {
    case ATOM_DSA:
      add_key(keys,
              make_keypair(ATOM_SSH_DSS, PUBLIC_KEY(v), s));
      break;
    case ATOM_DSA_SHA256:
      add_key(keys,
              make_keypair(ATOM_SSH_DSA_SHA256_LOCAL, PUBLIC_KEY(v), s));
      break;
    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      add_key(keys,
              make_keypair(ATOM_SSH_RSA, PUBLIC_KEY(v), s));
      break;

    default:
      werror("read_host_key: Unexpected algorithm %a.\n", algorithm_name);
    }
  return 1;
}

const char *argp_program_version
= "lshd (" PACKAGE_STRING ")";

const char *argp_program_bug_address = BUG_ADDRESS;

enum {  
  OPT_INTERFACE = 0x201,
  OPT_DAEMONIC,
  OPT_PIDFILE,
  OPT_NO_PIDFILE,
  OPT_CORE,
  OPT_NO_SETSID,
  OPT_SERVICE,
  OPT_ADD_SERVICE,
};

static const struct argp_option
lshd_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "interface", OPT_INTERFACE, "INTERFACE", 0,
    "Listen on this network interface.", 0 }, 
  { "port", 'p', "PORT", 0, "Listen on this port.", 0 },
  { "host-key", 'h', "FILE", 0, "Location of the server's private key.", 0},

  { "service", OPT_SERVICE, "NAME { COMMAND LINE }", 0,
    "Service to offer.", 0 },
  { "add-service", OPT_ADD_SERVICE, "NAME { COMMAND LINE }", 0,
    "Service to offer. Unlike --service does not override other services "
    "listed in the config file.", 0 },

  { NULL, 0, NULL, 0, "Daemonic behaviour:", 0 },
  { "daemonic", OPT_DAEMONIC, NULL, 0, "Run in the background, redirect stdio to /dev/null, chdir to /, and use syslog.", 0 },
  { "pid-file", OPT_PIDFILE, "FILE", 0, "Create a pid file. When running in daemonic mode, "
    "the default is " FILE_LSHD_PID ".", 0 },
  { "no-pid-file", OPT_NO_PIDFILE, NULL, 0, "Don't use any pid file. Default in non-daemonic mode.", 0 },
  { "enable-core", OPT_CORE, NULL, 0, "Dump core on fatal errors (disabled by default).", 0 },
  { "no-setsid", OPT_NO_SETSID, NULL, 0, "Don't start a new session.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
lshd_argp_children[] =
{
  { &server_argp, 0, "", 0 },
  { &algorithms_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static struct lshd_interface *
parse_interface(size_t length, const char *arg)
{
  const char *sep = memchr(arg, ':', length);

  if (sep)
    {
      size_t name_length = sep - arg;
      if (name_length + 1 == length)
	return NULL;
      else
	{
	  NEW(lshd_interface, self);

	  self->name = ssh_format("%ls", name_length, arg);
	  self->port = ssh_format("%ls", length - name_length - 1, sep + 1);
	  return self;
	}
    }
  else
    {
      NEW(lshd_interface, self);

      self->name = ssh_format("%ls", length, arg);
      self->port = NULL;
      return self;
    }
}

static error_t
lshd_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lshd_config, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      state->child_inputs[1] = self->algorithms;
       break;

    case ARGP_KEY_END:
      if (object_queue_is_empty(&self->ctx->service_config->services))
	{
	  struct service_entry *entry
	    = make_service_entry("ssh-userauth", NULL);

	  /* Note: FILE_LSHD_USERAUTH is relative to libexecdir. */
	  arglist_push (&entry->args, FILE_LSHD_USERAUTH);

	  arglist_push (&entry->args, "--session-id");
	  arglist_push (&entry->args, "$(session_id)");
	  
	  /* Propagate werror-related options. */
	  if (self->super.super.verbose > 0)
	    arglist_push (&entry->args, "-v");
	  if (self->super.super.quiet > 0)
	    arglist_push (&entry->args, "-q");
	  if (self->super.super.debug > 0)
	    arglist_push (&entry->args, "--debug");
	  if (self->super.super.trace > 0)
	    arglist_push (&entry->args, "--trace");

	  assert (entry->args.argc > 0);
	  object_queue_add_head (&self->ctx->service_config->services,
				 &entry->super);
	}
      break;

    case OPT_INTERFACE:
      {
	struct lshd_interface *interface = parse_interface(strlen(arg), arg);
	if (!interface)
	  argp_error(state, "Invalid interface `%s'\n", arg);

	object_queue_add_tail(&self->interfaces, &interface->super);
	self->interfaces_override_config_file = 1;
	break;
      }
    case 'p':
      string_queue_add_tail(&self->ports, make_string(arg));
      self->ports_override_config_file = 1;
      break;

    case 'h':
      if (!self->hostkey)
	self->hostkey = make_string(arg);
      break;

    case OPT_SERVICE:
      self->ctx->service_config->override_config_file = 1;
      /* Fall through */
    case OPT_ADD_SERVICE:
      service_config_argp(self->ctx->service_config,
			  state, "service", arg);      
      break;

    case OPT_DAEMONIC:
      self->daemonic = 1;
      break;

    case OPT_PIDFILE:
      if (!self->pid_file)
	{
	  self->pid_file = make_string(arg);
	  self->use_pid_file = 1;
	}
      break;

    case OPT_NO_PIDFILE:
      self->use_pid_file = 0;
      break;

    case OPT_CORE:
      self->corefile = 1;
      break;

    case OPT_NO_SETSID:
      self->daemon_flags |= DAEMON_FLAG_NO_SETSID;
      break;
    }
  return 0;
}

static const struct argp
lshd_argp =
{ lshd_options, lshd_argp_parser,
  NULL,
  "Server for the ssh-2 protocol.",
  lshd_argp_children,
  NULL, NULL
};

static const struct config_option
lshd_config_options[] = {
  { 'h', "hostkey", CONFIG_TYPE_STRING,
    "Location of server's private host key", FILE_LSHD_HOST_KEY },
  { OPT_INTERFACE, "interface", CONFIG_TYPE_STRING,
    "Interface to listen to.", NULL },
  { 'p', "port", CONFIG_TYPE_STRING,
    "Port number or service name.", "ssh" },
  { OPT_SERVICE, "service", CONFIG_TYPE_LIST, "Service to offer.",
    "ssh-userauth = { lshd-userauth --session-id $(session_id) "
    "--use-example-config }" },

  { OPT_CORE, "enable-core-file", CONFIG_TYPE_BOOL,
    "Allow lshd to dump core if it crashes.", "no" },
  { OPT_PIDFILE, "pid-file", CONFIG_TYPE_STRING,
    "Location of pid file.", NULL },

  { 0, NULL, 0, NULL, NULL }
  
};

static int
lshd_config_handler(int key, uint32_t value, const uint8_t *data,
		    struct config_parser_state *state)
{
  CAST_SUBTYPE(lshd_config, self, state->input);
  switch (key)
    {
    case CONFIG_PARSE_KEY_INIT:
      state->child_inputs[0] = &self->super.super;
      break;
    case CONFIG_PARSE_KEY_END:
      {
	/* Set up defaults, and interpret values. */
	struct int_list *hostkey_algorithms;
	struct lshd_context *ctx = self->ctx;

	if (string_queue_is_empty (&self->ports))
	  string_queue_add_tail(&self->ports, make_string("22"));

	if (self->daemonic > 0)
	  {
	    if (self->super.super.syslog < 0)
	      self->super.super.syslog = 1;

	    if (self->use_pid_file < 0)
	      self->use_pid_file = 1;
	  }

	if (self->use_pid_file < 0)
	  self->use_pid_file = 0;

	if (self->use_pid_file && ! self->pid_file)
	  self->pid_file = make_string(FILE_LSHD_PID);

	if (self->corefile < 0)
	  self->corefile = 1;

	/* FIXME: The default should depend on ENV_LSHD_CONFIG_DIR. */
	if (!read_host_key((self->hostkey
			    ? lsh_get_cstring(self->hostkey)
			    : FILE_LSHD_HOST_KEY),
			   all_signature_algorithms(),
			   ctx->keys))
	  {
	    werror("No hostkey.\n");
	    return ENOENT;
	  }
	
	ALIST_SET(ctx->super.algorithms,
		  ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
		  &make_server_dh_exchange(make_dh_group14(&nettle_sha1),
					   ctx->keys)->super);

	hostkey_algorithms
	  = filter_algorithms(ctx->keys,
			      self->algorithms->hostkey_algorithms);

	if (!hostkey_algorithms)
	  {
	    werror("No hostkey algorithms advertised.\n");
	    hostkey_algorithms = make_int_list(1, ATOM_NONE, -1);
	  }
	  
	ctx->super.kexinit
	  = make_kexinit_info(make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
			      hostkey_algorithms,
			      self->algorithms->crypto_algorithms,
			      self->algorithms->mac_algorithms,
			      self->algorithms->compression_algorithms,
			      make_int_list(0, -1));
	
	break;
      }
      
    case 'h':
      if (!self->hostkey)
	self->hostkey = ssh_format("%ls", value, data);
      break;

    case OPT_INTERFACE:
      if (!self->interfaces_override_config_file)
	{
	  struct lshd_interface *interface = parse_interface(value, data);
	  if (!interface)
	    /* FIXME: Abort config parsing somehow? */
	    werror("Invalid interface `%s'\n", value, data);
	  else
	    object_queue_add_tail(&self->interfaces, &interface->super);
	}
      break;

    case 'p':
      if (!self->ports_override_config_file)
	string_queue_add_tail(&self->ports, ssh_format("%ls", value, data));
      break;

    case OPT_SERVICE:
      if (!service_config_option(self->ctx->service_config,
				 "service", value, data))
	return EINVAL;
      break;

    case OPT_CORE:
      if (self->corefile < 0)
	self->corefile = value;
      break;

    case OPT_PIDFILE:
      if (!self->pid_file)
	{
	  self->pid_file = ssh_format("%ls", value, data);
	  self->use_pid_file = 1;
	}
      break;
    }
  return 0;  
}

static const struct config_parser *
lshd_config_children[] = {
  &werror_config_parser,
  NULL
};

static const struct config_parser
lshd_config_parser = {
  lshd_config_options,
  lshd_config_handler,
  lshd_config_children
};

int
main(int argc, char **argv)
{
  struct lshd_config *config;
  enum daemon_mode mode = DAEMON_NORMAL;
	  
  struct resource_list *resources = make_resource_list();;

  /* Do this first and unconditionally, before we start to initialize i/o */
  daemon_close_fds();
  
#if HAVE_SETRLIMIT && HAVE_SYS_RESOURCE_H
  {
    /* Try to increase max number of open files, ignore any error */

    struct rlimit r;

    r.rlim_max = RLIM_INFINITY;
    r.rlim_cur = RLIM_INFINITY;

    setrlimit(RLIMIT_NOFILE, &r);
  }
#endif

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  config = make_lshd_config(make_lshd_context());

  argp_parse(&lshd_argp, argc, argv, 0, NULL, config);

  /* Put this check after argument parsing, to make the --help option
     work. */
  if (!random_init_system())
    {
      werror("No randomness generator available.\n");
      exit(EXIT_FAILURE);
    }

  if (config->daemonic)
    {
      mode = daemon_detect();

      if (mode == DAEMON_INETD)
	{
	  werror("Spawning from inetd not yet supported.\n");
	  return EXIT_FAILURE;
	}
      else
	{
	  if (!daemon_dup_null(STDIN_FILENO)
	      || !daemon_dup_null(STDOUT_FILENO))
	    return EXIT_FAILURE;
	}
    }

  if (!config->corefile && !daemon_disable_core())
    {
      werror("Disabling of core dumps failed.\n");
      return EXIT_FAILURE;
    }

  io_init();
  
  if (!open_all_ports(config->ctx, resources,
		      &config->interfaces,
		      &config->ports))
    {
      werror("Could not open any listen ports.\n");
      return EXIT_FAILURE;
    }
  if (config->daemonic)
    {
      if (!daemon_init(mode, config->daemon_flags))
	{
	  werror("Setting up daemonic environment failed.\n");
	  return EXIT_FAILURE;
	}
    }

  if (config->use_pid_file)
    {
      if (daemon_pidfile(lsh_get_cstring(config->pid_file)))
	{
	  remember_resource(resources, 
			    make_pid_file_resource(config->pid_file));
	  /* The string is owned by the resource now, so forget it. */
	  config->pid_file = NULL;
	}
      else
	{
	  werror("lshd seems to be running already.\n");
	  return EXIT_FAILURE;
	}
    }

  io_signal_handler(SIGHUP,
		    make_sighup_close_callback(&resources->super));
  
  /* Ignore status from child processes */
  signal(SIGCHLD, SIG_IGN);
    
  io_run();

  return EXIT_SUCCESS;
}
