/* lsh.c
 *
 * Client main program.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2005 Niels Möller
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
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "nettle/sexp.h"
/* For struct spki_iterator */
#include "spki/parse.h"

#include "alist.h"
#include "arglist.h"
#include "atoms.h"
#include "channel.h"
#include "charset.h"
#include "client.h"
#include "compress.h"
#include "connection_commands.h"
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "gateway.h"
#include "gateway_commands.h"
#include "lsh_string.h"
#include "randomness.h"
#include "reaper.h"
#include "sexp.h"
#include "service.h"
#include "ssh.h"
#include "ssh_write.h"
#include "tcpforward.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh_argp.h"

#include "lsh.c.x"

#define CONNECTION_WRITE_THRESHOLD 1000
#define CONNECTION_WRITE_BUFFER_SIZE (100*SSH_MAX_PACKET)

/* GABA:
   (class
     (name connection)
     (super ssh_connection)
     (vars
       (transport . int)
       (reader object service_read_state)
       (writer object ssh_write_state)))
*/

/* FIXME: Duplicates code in lshd-connection */

static void
kill_connection(struct resource *s)
{
  CAST(connection, self, s);
  if (self->super.super.alive)
    {
      werror("kill_connection\n");

      self->super.super.alive = 0;      

      KILL_RESOURCE_LIST(self->super.resources);

      io_close_fd(self->transport);
      self->transport = -1;
    }
}

static void
write_packet(struct connection *connection,
	     struct lsh_string *packet)
{
  uint32_t done;
  int msg;
  
  assert(lsh_string_length(packet) > 0);
  msg = lsh_string_data(packet)[0];
  trace("Writing packet of type %T (%i)\n", msg, msg);
  debug("packet contents: %xS\n", packet);

  /* Sequence number not supported */
  packet = ssh_format("%i%fS", 0, packet);
  
  done = ssh_write_data(connection->writer,
			connection->transport, 0, 
			STRING_LD(packet));
  lsh_string_free(packet);

  /* FIXME: Check if we're filling up the buffer; if so we must stop
     channels from sending more data. */
  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (connection->writer->length)
	{
	  /* FIXME: Install a write callback */
	  werror("write_packet: ssh_write_data couldn't write all data.\n");
	}
    }
  else
    {
      werror("write_packet: Write failed: %e\n", errno);
      exit(EXIT_FAILURE);
    }
}

static void
disconnect(struct connection *connection, uint32_t reason, const char *msg)
{
  werror("disconnecting: %z.\n", msg);

  write_packet(connection,
	       format_disconnect(reason, msg, ""));

  /* FIXME: If the write buffer is full, the disconnect message will
     likely be lost. */
  KILL_RESOURCE(&connection->super.super);
}

static void
service_start_read(struct connection *self);

static void *
oop_read_service(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(connection, self, (struct lsh_object *) state);

  assert(event == OOP_READ);

  for (;;)
    {
      enum service_read_status status;

      uint32_t seqno;
      uint32_t length;      
      const uint8_t *packet;
      const char *error_msg;
      uint8_t msg;
      
      status = service_read_packet(self->reader, fd,
				   &error_msg,
				   &seqno, &length, &packet);
      fd = -1;

      switch (status)
	{
	case SERVICE_READ_IO_ERROR:
	  werror("Read failed: %e\n", errno);
	  exit(EXIT_FAILURE);
	  break;
	case SERVICE_READ_PROTOCOL_ERROR:
	  werror("Invalid data from transport layer: %z\n", error_msg);
	  exit(EXIT_FAILURE);
	  break;
	case SERVICE_READ_EOF:
	  werror("Transport layer closed\n", error_msg);
	  return OOP_HALT;
	  break;
	case SERVICE_READ_PUSH:
	case SERVICE_READ_PENDING:
	  return OOP_CONTINUE;

	case SERVICE_READ_COMPLETE:
	  if (!length)
	    disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
		       "lshd-connection received an empty packet");

	  msg = packet[0];

	  if (msg < SSH_FIRST_CONNECTION_GENERIC)
	    /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
	    disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
		       "lshd-connection received a transport or userauth layer packet");

	  else if (!channel_packet_handler(&self->super, length, packet))
	    write_packet(self, format_unimplemented(seqno));	    
	}
    }
}

static void
service_start_read(struct connection *self)
{
  global_oop_source->on_fd(global_oop_source,
			   self->transport, OOP_READ,
			   oop_read_service, self);  
}

static void
do_write_packet(struct ssh_connection *s, struct lsh_string *packet)
{
  CAST(connection, self, s);

  write_packet(self, packet);
}

static void
do_disconnect(struct ssh_connection *s, uint32_t reason, const char *msg)
{
  CAST(connection, self, s);
  disconnect(self, reason, msg);  
}

static struct connection *
make_connection(int fd)
{
  NEW(connection, self);
  init_ssh_connection(&self->super, kill_connection, do_write_packet, do_disconnect);

  io_register_fd(fd, "lsh transport connection");

  self->transport = fd;
  self->reader = make_service_read_state();
  service_start_read(self);

  self->writer = make_ssh_write_state(CONNECTION_WRITE_BUFFER_SIZE);

  return self;
}

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel
 *
 * NOTE: Large windows seem to trig a bug in sshd2. */
#define WINDOW_SIZE 10000

/* GABA:
   (class
     (name lsh_options)
     (super client_options)
     (vars
       (home . "const char *")
       
       ;; (with_gateway . int)
       (transport_args . "struct arglist")
       ))
*/


static struct lsh_options *
make_options(struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);
  const char *home = getenv(ENV_HOME);
  struct randomness *r = make_user_random(home);
  const char *transport_program;
  
  init_client_options(&self->super, r, handler, exit_code);

  self->home = home;
#if 0
  self->with_gateway = 0;
#endif

  arglist_init(&self->transport_args);

  /* Set argv[0] */
  GET_FILE_ENV(transport_program, LSH_TRANSPORT);
  arglist_push(&self->transport_args, transport_program);
  
  return self;
}

/* Option parsing */

const char *argp_program_version
= "lsh-" VERSION ", secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

#define OPT_PUBLICKEY 0x201

#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204

#define OPT_HOST_DB 0x205

#define OPT_DH 0x206
#define OPT_SRP 0x207

#define OPT_HOSTKEY_ALGORITHM 0x210

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */

  /* Options passed on to lsh-transport. */
  
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
#if 0
  { "publickey", OPT_PUBLICKEY, NULL, 0,
    "Try publickey user authentication (default).", 0 },
  { "no-publickey", OPT_PUBLICKEY | ARG_NOT, NULL, 0,
    "Don't try publickey user authentication.", 0 },
#endif
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/host-acls", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new hostkey is received, append an ACL expressing trust in the key. "
    "In sloppy mode, the default is ~/.lsh/captured_keys.", 0 },
#if 0
#if WITH_SRP
  { "srp-keyexchange", OPT_SRP, NULL, 0, "Enable experimental SRP support.", 0 },
  { "no-srp-keyexchange", OPT_SRP | ARG_NOT, NULL, 0, "Disable experimental SRP support (default).", 0 },
#endif /* WITH_SRP */

  { "dh-keyexchange", OPT_DH, NULL, 0,
    "Enable DH support (default, unless SRP is being used).", 0 },

  { "no-dh-keyexchange", OPT_DH | ARG_NOT, NULL, 0, "Disable DH support.", 0 },
#endif

  { "crypto", 'c', "Algorithm", 0, "", 0 },
  { "compression", 'z', "Algorithm",
    OPTION_ARG_OPTIONAL, "Default is zlib.", 0 },
  { "mac", 'm', "Algorithm", 0, "", 0 },
  { "hostkey-algorithm", OPT_HOSTKEY_ALGORITHM, "Algorithm", 0, "", 0 }, 
  
  /* Actions */
#if 0
  { "forward-remote-port", 'R', "remote-port:target-host:target-port",
    0, "", CLIENT_ARGP_ACTION_GROUP },
  { "gateway", 'G', NULL, 0, "Setup a local gateway", 0 },
#endif

#if WITH_X11_FORWARD
  /* FIXME: Perhaps this should be moved from lsh.c to client.c? It
   * doesn't work with lshg. Or perhaps that can be fixed?
   * About the same problem applies to -R. */
  
  { "x11-forward", 'x', NULL, 0, "Enable X11 forwarding.", CLIENT_ARGP_MODIFIER_GROUP },
  { "no-x11-forward", 'x' | ARG_NOT, NULL, 0,
    "Disable X11 forwarding (default).", 0 },
#endif
  
  { NULL, 0, NULL, 0, NULL, 0 }
};


static const struct argp_child
main_argp_children[] =
{
  { &client_argp, 0, "", 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

#define CASE_ARG(opt, attr, none)		\
  case opt:					\
    if (self->super.not)			\
      {						\
        self->super.not = 0;			\
						\
      case opt | ARG_NOT:			\
        self->attr = none;			\
        break;					\
      }						\
      						\
    self->attr = arg;				\
    break

#define CASE_FLAG(opt, flag)			\
  case opt:					\
    if (self->super.not)			\
      {						\
        self->super.not = 0;			\
						\
      case opt | ARG_NOT:			\
        self->flag = 0;				\
        break;					\
      }						\
      						\
    self->flag = 1;				\
    break

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      state->child_inputs[1] = NULL;
      break;
      
    case ARGP_KEY_END:
      if (self->super.inhibit_actions)
	break;

      if (!self->home)
	{
	  argp_error(state, "No home directory. Please set HOME in the environment.");
	  break;
	}

#if 0
      if (!self->super.random)
	argp_failure( state, EXIT_FAILURE, 0,  "No randomness generator available.");

      if (self->with_dh_keyexchange < 0)
	self->with_dh_keyexchange = !self->with_srp_keyexchange;
      
      if (self->with_dh_keyexchange || self->with_srp_keyexchange)
	{
	  int i = 0;
	  self->kex_algorithms 
	    = alloc_int_list(2 * self->with_dh_keyexchange + self->with_srp_keyexchange);
	    
#if WITH_SRP	    
	  if (self->with_srp_keyexchange)
	    {
	      LIST(self->kex_algorithms)[i++] = ATOM_SRP_RING1_SHA1_LOCAL;
	      ALIST_SET(self->algorithms->algorithms,
			ATOM_SRP_RING1_SHA1_LOCAL,
			&make_srp_client(make_srp1(self->super.random),
					 self->super.tty,
					 ssh_format("%lz", self->super.user))
			->super);
	    }
#endif /* WITH_SRP */
	  if (self->with_dh_keyexchange)
	    {
	      struct keyexchange_algorithm *dh2
		= make_dh_client(make_dh14(self->super.random));
	      
	      LIST(self->kex_algorithms)[i++] = ATOM_DIFFIE_HELLMAN_GROUP14_SHA1;
	      ALIST_SET(self->algorithms->algorithms,
			ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
			&dh2->super);

	      LIST(self->kex_algorithms)[i++] = ATOM_DIFFIE_HELLMAN_GROUP1_SHA1;
	      ALIST_SET(self->algorithms->algorithms,
			ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
			&make_dh_client(make_dh1(self->super.random))
			->super);
	    }
	}
      else
	argp_error(state, "All keyexchange algorithms disabled.");
	
      {
	struct lsh_string *tmp = NULL;
	const char *s = NULL;
	  
	if (self->capture)
	  s = self->capture;
	else if (self->sloppy)
	  {
	    tmp = ssh_format("%lz/.lsh/captured_keys", self->home);
	    s = lsh_get_cstring(tmp);
	  }
	if (s)
	  {
	    static const struct report_exception_info report =
	      STATIC_REPORT_EXCEPTION_INFO(EXC_IO, EXC_IO,
					   "Writing new ACL: ");

	    self->capture_file
	      = io_write_file(s,
			      O_CREAT | O_APPEND | O_WRONLY,
			      0600, 
			      make_report_exception_handler
			      (&report,
			       &default_exception_handler,
			       HANDLER_CONTEXT));
	    if (!self->capture_file)
	      werror("Failed to open '%z' %e.\n", s, errno);
	  }
	lsh_string_free(tmp);
      }
#endif
      
      /* We can't add the gateway action immediately when the -G
       * option is encountered, as we need the name and port of the
       * remote machine (self->super.remote) first.
       *
       * This breaks the rule that actions should be performed in the
       * order they are given on the command line. Since we usually
       * want the gateway action first (e.g. when the testsuite runs
       * lsh -G -B, and expects the gateway to be up by the time lsh
       * goes into the background), we prepend it on the list of
       * actions. */
#if 0
      if (self->start_gateway)
	{
	  struct local_info *gateway;
	  if (!self->super.local_user)
	    {
	      argp_error(state, "You have to set LOGNAME in the environment, "
			 " if you want to use the gateway feature.");
	      break;
	    }
	  gateway = make_gateway_address(self->super.local_user,
					 self->super.user,
					 self->super.target);

	  if (!gateway)
	    {
	      argp_error(state, "Local or remote user name, or the target host name, are too "
			 "strange for the gateway socket name construction.");
	      break;
	    }
	      
	  client_prepend_action(&self->super,
				make_gateway_setup(gateway));
	}
#endif
      if (object_queue_is_empty(&self->super.actions))
	{
	  argp_error(state, "No actions given.");
	  break;
	}

      break;

    case 'i':
      arglist_push(&self->transport_args, "--identity");
      arglist_push(&self->transport_args, arg);
      break;

#if 0
      CASE_FLAG(OPT_PUBLICKEY, with_publickey);
#endif
    case OPT_HOST_DB:
      arglist_push(&self->transport_args, "--host-db");
      arglist_push(&self->transport_args, arg);
      break;

    case OPT_SLOPPY:
      arglist_push(&self->transport_args, "--sloppy-host-authentication");
      break;

    case OPT_STRICT:
      arglist_push(&self->transport_args, "--strict-host-authentication");
      break;

    case OPT_CAPTURE:
      arglist_push(&self->transport_args, "--capture-to");
      arglist_push(&self->transport_args, arg);
      break;

    case 'c':
      arglist_push(&self->transport_args, "-c");
      arglist_push(&self->transport_args, arg);
      break;

    case 'm':
      arglist_push(&self->transport_args, "-m");
      arglist_push(&self->transport_args, arg);
      break;

    case 'z':
      if (!arg)
	arglist_push(&self->transport_args, "-z");
      else
	arglist_push_optarg(&self->transport_args, "-z", arg);
      break;

#if 0

    CASE_FLAG(OPT_DH, with_dh_keyexchange);
    CASE_FLAG(OPT_SRP, with_srp_keyexchange);
#endif

#if 0
    case 'R':
      {
	uint32_t listen_port;
	struct address_info *target;

	if (!client_parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	client_add_action(&self->super, make_forward_remote_port
			  (make_address_info((self->super.with_remote_peers
					      ? ssh_format("%lz", "0.0.0.0")
					      : ssh_format("%lz", "127.0.0.1")),
					     listen_port),
			   target));

	self->super.remote_forward = 1;
	break;
      }

    CASE_FLAG('G', with_gateway);
#endif
#if WITH_X11_FORWARD
    CASE_FLAG('x', super.with_x11);
#endif
    }

  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  ( "host\n"
    "host command ..."), 
  ( "Connects to a remote machine\v"
    "Connects to the remote machine, and then performs one or more actions, "
    "i.e. command execution, various forwarding services. The default "
    "action is to start a remote interactive shell or execute a given "
    "command on the remote machine." ),
  main_argp_children,
  NULL, NULL
};

/* GABA:
   (class
     (name lsh_default_handler)
     (super exception_handler)
     (vars
       (status . "int *")))
*/

static void
do_lsh_default_handler(struct exception_handler *s,
		       const struct exception *e)
{
  CAST(lsh_default_handler, self, s);

  if (e->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, exc, e);
      *self->status = EXIT_FAILURE;
      
      werror("%z, (errno = %i)\n", e->msg, exc->error);
    }
  else
    switch(e->type)
      {
      case EXC_RESOLVE:
      case EXC_GLOBAL_REQUEST:
      case EXC_CHANNEL_REQUEST:
      case EXC_CHANNEL_OPEN:

	werror("%z\n", e->msg);
	*self->status = EXIT_FAILURE;
	break;
      default:
	*self->status = EXIT_FAILURE;
	EXCEPTION_RAISE(self->super.parent, e);
      }
}

static struct exception_handler *
make_lsh_default_handler(int *status, struct exception_handler *parent,
			 const char *context)
{
  NEW(lsh_default_handler, self);
  self->super.parent = parent;
  self->super.raise = do_lsh_default_handler;
  self->super.context = context;

  self->status = status;

  return &self->super;
}

static void
transport_exit_callback(struct exit_callback *s UNUSED,
			int signalled, int core, int value)
{
  if (signalled)
    {
      werror("Transport process killed by %s (signal %d)%s.\n",
	     STRSIGNAL(value), value, core ? " (core dumped)" : "");
      /* FIXME: Design and document error code values. */
      exit(17);
    }
  else if (value)
    {
      werror("Transport process exited with error code %d.\n", value);
      exit(value);
    }
  else
    {
      werror("Transport process exited successfully.\n");
      /* Do nothing */
    }
}

static struct exit_callback *
make_transport_exit_callback(void)
{
  NEW(exit_callback, self);
  self->exit = transport_exit_callback;
  return self;
}

static struct connection *
fork_lsh_transport(struct lsh_options *options)
{
  int pipe[2];
  pid_t child;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0)
    {
      werror("fork_lsh_transport: socketpair failed: %e\n", errno);
      return NULL;
    }
  child = fork();
  if (child < 0)
    {
      werror("fork_lsh_transport: fork failed: %e\n", errno);
      close(pipe[0]);
      close(pipe[1]);
      return NULL;
    }
  else if (child)
    {
      /* Parent process */
      struct connection *connection;
      close(pipe[1]);
      
      reaper_handle(child, make_transport_exit_callback());
      connection = make_connection(pipe[0]);

      gc_global(&connection->super.super);
      return connection;
    }
  else
    {
      /* Child process */
      char **argv;
      
      close(pipe[0]);
      dup2(pipe[1], STDIN_FILENO);
      dup2(pipe[1], STDOUT_FILENO);
      close(pipe[1]);

      if (verbose_flag)
	arglist_push(&options->transport_args, "-v");
      if (quiet_flag)
	arglist_push(&options->transport_args, "-q");	
      if (debug_flag)
	arglist_push(&options->transport_args, "--debug");
      if (trace_flag)
	arglist_push(&options->transport_args, "--trace");
      
      arglist_push(&options->transport_args, "-p");
      arglist_push(&options->transport_args, options->super.port);
      arglist_push(&options->transport_args, options->super.target);
      
      argv = (char **) options->transport_args.argv;
#if 0
      {
	fprintf(stderr, "argc = %d\n", options->transport_args.argc);
	
	int i;
	for (i = 0; argv[i]; i++)
	  fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
      }
#endif
      verbose("Starting %z.\n", argv[0]);
      execv(argv[0], argv);
      werror("fork_lsh_transport: exec failed: %e\n", errno);
      _exit(EXIT_FAILURE);
    }
}

int
main(int argc, char **argv, const char** envp)
{
  struct lsh_options *options;
  struct connection *connection;
  
  /* Default exit code if something goes wrong. */
  int lsh_exit_code = 17;

  struct exception_handler *handler
    = make_lsh_default_handler(&lsh_exit_code, &default_exception_handler,
			       HANDLER_CONTEXT);

  io_init();
  reaper_init();
  
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  options = make_options(handler, &lsh_exit_code);

  if (!options)
    return EXIT_FAILURE;

  envp_parse(&main_argp, envp, "LSHFLAGS=", ARGP_IN_ORDER, options);
  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);

  connection = fork_lsh_transport(options);
  if (!connection)
    exit(EXIT_FAILURE);

  /* Contains session channels to be opened. */
  remember_resource(connection->super.resources,
		    &options->super.resources->super);
		    
  {
    FOR_OBJECT_QUEUE(&options->super.actions, n)
      {
	CAST_SUBTYPE(command, action, n);
	COMMAND_CALL(action, connection, &discard_continuation, handler);
      }
  }
  
  io_run();
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  return lsh_exit_code;
}
