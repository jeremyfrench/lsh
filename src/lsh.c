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
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io_commands.h"
#include "gateway.h"
#include "lsh_string.h"
#include "randomness.h"
#include "reaper.h"
#include "sexp.h"
#include "ssh.h"
#include "ssh_write.h"
#include "tcpforward.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh_argp.h"

struct command_2 gateway_accept;
#define GATEWAY_ACCEPT (&gateway_accept.super.super)

#include "lsh.c.x"

/* Flow control status: If the buffer for writing to the transport
   layer gets full, we stop reading on all channels, and we stop
   reading from all gateways. FIXME: Missing pieces:

   1. If a channel is somewhere in the opening handshake when we
      detect the transport buffer getting full, it is not signalled to
      stop, and might start generating data when the handshake is
      finished.

*/

/* FIXME: Move to client.h and client.c? */


/* (gateway_accept main-connection gateway-connection) */
DEFINE_COMMAND2(gateway_accept)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(client_connection, connection, a1);
  CAST(listen_value, lv, a2);

  static const char hello[LSH_HELLO_LINE_LENGTH]
    = "LSH " STRINGIZE(LSH_HELLO_VERSION) " OK lsh-transport";
  
  struct gateway_connection *gateway
    = make_gateway_connection(connection, lv->fd);

  int error = gateway_write_data (gateway, sizeof(hello), hello);
  if (error)
    {
      werror ("Sending gateway hello message failed: %e\n", error);
      KILL_RESOURCE (&gateway->super.super);
      return;
    }

  if (!connection->write_blocked)
    gateway_start_read(gateway);

  /* Kill gateway connection if the main connection goes down. */
  remember_resource(connection->gateway_connections, &gateway->super.super);

  COMMAND_RETURN(c, gateway);
}

/* GABA:
   (expr
     (name make_gateway_setup)
     (storage static)
     (params
       (local object local_info))
     (expr
       (lambda (connection)
         (connection_remember connection
	   (listen_local
	     (lambda (peer)
	       (gateway_accept connection peer))
	       ;; prog1, to delay binding until we are connected.
	     (prog1 local connection) )))))
*/

#if 0
FIXME: XXX
DEFINE_CHANNEL_OPEN(channel_open_x11)
	(struct channel_open *s UNUSED,
	 const struct channel_open_info *info,
	 struct simple_buffer *args)
{
  CAST(client_connection, self, info->connection);
  struct resource *handler = resource_list_top(self->x11_displays);

  if (handler)
    {
      client_x11_open(handler, info, args);
    }
  else
    channel_open_deny(info,
		      SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
		      "Unexpected x11 request");
}
#endif

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

       ; 0 means no, 1 means yes, -1 means use if available.
       (use_gateway . int)
       ; 0 means no, 1 means yes, -1 means start if not already available.
       (start_gateway . int)
       (stop_gateway . int)

       (gateway object local_info)

       (transport_args . "struct arglist")))
*/


static struct lsh_options *
make_options(struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);
  const char *home = getenv(ENV_HOME);
#if 0
  struct randomness *r = make_user_random(home);
#endif
  const char *transport_program;

  /* Randomness generator used only for fake X11 cookies, and X11
     support is currently disabled */
  init_client_options(&self->super, NULL, handler, exit_code);

  self->home = home;

  self->use_gateway = -1;
  self->start_gateway = 0;
  self->stop_gateway = 0;
  self->gateway = NULL;

  arglist_init(&self->transport_args);

  /* Set argv[0] */
  GET_FILE_ENV(transport_program, LSH_TRANSPORT);
  arglist_push(&self->transport_args, transport_program);
  
  return self;
}

/* Option parsing */

const char *argp_program_version
= "lsh (" PACKAGE_STRING "), secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

enum {
  ARG_NOT = 0x400,

  OPT_PUBLICKEY = 0x201,
  OPT_SLOPPY,
  OPT_STRICT,
  OPT_CAPTURE,

  OPT_HOST_DB,

  OPT_DH,
  OPT_SRP,

  OPT_HOSTKEY_ALGORITHM,
  
  OPT_USE_GATEWAY,
  OPT_START_GATEWAY,
  OPT_STOP_GATEWAY
};

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

  { "crypto", 'c', "ALGORITHM", 0, "", 0 },
  { "compression", 'z', "ALGORITHM", OPTION_ARG_OPTIONAL,
    "Enable compression. Default algorithm is zlib.", 0 },
  { "mac", 'm', "ALGORITHM", 0, "Select MAC algorithm", 0 },
  { "hostkey-algorithm", OPT_HOSTKEY_ALGORITHM, "ALGORITHM", 0,
    "Select host authentication algorithm.", 0 }, 
  
  /* Actions */
  /* FIXME: Remote forwarding and X11 forwarding doesn't work over a gateway. */
  { "forward-remote-port", 'R', "REMOTE-PORT:TARGET-HOST:TARGET-PORT", 0,
    "Forward TCP/IP connections at a remote port", CLIENT_ARGP_ACTION_GROUP },
#if WITH_X11_FORWARD
  { "x11-forward", 'x', NULL, 0, "Enable X11 forwarding.", CLIENT_ARGP_MODIFIER_GROUP },
  { "no-x11-forward", 'x' | ARG_NOT, NULL, 0,
    "Disable X11 forwarding (default).", 0 },
#endif

  /* Gateway options */
  { "use-gateway", OPT_USE_GATEWAY, NULL, 0,
    "Always use a local gateway", 0 },
  { "no-use-gateway", OPT_USE_GATEWAY | ARG_NOT, NULL, 0,
    "Never use a local gateway", 0 },
  { "gateway", 'G', NULL, 0,
    "Use any existing gateway; if none exists, start a new one.", 0 },
  { "start-gateway", OPT_START_GATEWAY, NULL, 0,
    "Stop any existing gateway, and start a new one.", 0 },
  { "stop-gateway", OPT_START_GATEWAY, NULL, 0,
    "Stop any existing gateway. Disables all other actions.", 0 },

  { NULL, 0, NULL, 0, NULL, 0 }
};


static const struct argp_child
main_argp_children[] =
{
  { &client_argp, 0, "", 0 },
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
      break;
      
    case ARGP_KEY_END:
      if (self->super.inhibit_actions)
	break;

      if (!self->home)
	{
	  argp_error(state, "No home directory. Please set HOME in the environment.");
	  break;
	}

      if (self->start_gateway > 0 && self->use_gateway > 0)
	{
	  argp_error(state, "--start-gateway and --use-gateway are "
		     "mutually exclusive.");
	  break;
	}
      /* We can't add the gateway action immediately when the -G
       * option is encountered, as we need the name and port of the
       * remote machine (self->super.remote) first.
       */

      if (self->start_gateway || self->stop_gateway || self->use_gateway)
	{
	  if (!self->super.local_user)
	    {
	      argp_error(state, "You have to set LOGNAME in the environment, "
			 " if you want to use the gateway feature.");
	      break;
	    }
	  self->gateway = make_gateway_address(self->super.local_user,
					       self->super.user,
					       self->super.target);

	  if (!self->gateway)
	    {
	      argp_error(state, "Local or remote user name, or the target host name, are too "
			 "strange for the gateway socket name construction.");
	      break;
	    }
	}

      if (object_queue_is_empty(&self->super.actions) && !self->stop_gateway)
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

    case 'R':
      {
	unsigned long listen_port;
	struct address_info *target;

	if (!client_parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	client_add_action(&self->super, forward_remote_port
			  (make_address_info((self->super.with_remote_peers
					      ? ssh_format("%lz", "0.0.0.0")
					      : ssh_format("%lz", "127.0.0.1")),
					     listen_port),
			   target));

	self->super.remote_forward = 1;
	break;
      }

    CASE_FLAG(OPT_USE_GATEWAY, use_gateway);

    case 'G':
      /* FIXME: It would be desirable to have this option also imply
	 that lsh is backgrounded when the primary actions are
	 completed. */
      self->start_gateway = -1;
      break;

    case OPT_START_GATEWAY:
      self->start_gateway = 1;
      self->stop_gateway = 1;
      break;

    case OPT_STOP_GATEWAY:
      self->stop_gateway = 1;
      break;

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

  if (e->type == EXC_IO_ERROR)
    werror("%z, %e\n", e->msg, e->subtype);

  else
    werror("%z\n", e->msg);

  /* For essential requests, like "shell" and "exec", the channel is
     just closed on errors. The channel request that we get exceptions
     for are the ones that are not essential. */
  if (e->type != EXC_CHANNEL_REQUEST)
    *self->status = EXIT_FAILURE;
}

static struct exception_handler *
make_lsh_default_handler(int *status, const char *context)
{
  NEW(lsh_default_handler, self);
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
      werror("Transport process killed by %s (signal %i)%s.\n",
	     STRSIGNAL(value), value, core ? " (core dumped)" : "");
      /* FIXME: Design and document error code values. */
      exit(17);
    }
  else if (value)
    {
      werror("Transport process exited with error code %i.\n", value);
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

static int
fork_lsh_transport(struct lsh_options *options)
{
  int pipe[2];
  pid_t child;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0)
    {
      werror("fork_lsh_transport: socketpair failed: %e\n", errno);
      return -1;
    }
  child = fork();
  if (child < 0)
    {
      werror("fork_lsh_transport: fork failed: %e\n", errno);
      close(pipe[0]);
      close(pipe[1]);
      return -1;
    }
  else if (child)
    {
      /* Parent process */
      close(pipe[1]);
      
      reaper_handle(child, make_transport_exit_callback());
      return pipe[0];
    }
  else
    {
      /* Child process */
      char **argv;
      int error_fd = get_error_stream();

      close(pipe[0]);
      dup2(pipe[1], STDIN_FILENO);
      dup2(pipe[1], STDOUT_FILENO);
      close(pipe[1]);

      if (error_fd >= 0 && error_fd != STDERR_FILENO)
	dup2(error_fd, STDERR_FILENO);

      arglist_push(&options->transport_args, "-l");
      arglist_push(&options->transport_args, options->super.user);

      if (options->super.super.verbose > 0)
	arglist_push(&options->transport_args, "-v");
      if (options->super.super.quiet > 0)
	arglist_push(&options->transport_args, "-q");	
      if (options->super.super.debug > 0)
	arglist_push(&options->transport_args, "--debug");
      if (options->super.super.trace > 0)
	arglist_push(&options->transport_args, "--trace");

      if (options->super.port)
	{
	  arglist_push(&options->transport_args, "-p");
	  arglist_push(&options->transport_args, options->super.port);
	}
      arglist_push(&options->transport_args, options->super.target);
      
      argv = (char **) options->transport_args.argv;

      verbose("Starting %z.\n", argv[0]);
      execv(argv[0], argv);
      werror("fork_lsh_transport: exec failed: %e\n", errno);
      _exit(EXIT_FAILURE);
    }
}

static int
process_hello_message(int fd)
{
  struct lsh_string *buf = lsh_string_alloc(LSH_HELLO_LINE_LENGTH);
  static const char expected[] = "LSH " STRINGIZE(LSH_HELLO_VERSION) " OK";

  int res = lsh_string_read (buf, 0, fd, LSH_HELLO_LINE_LENGTH);
  if (res < 0)
    {
      werror ("Reading local hello message failed: %e\n", errno);
    fail:
      lsh_string_free (buf);
      return 0;
    }
  if (!res)
    {
      werror ("Lost local connection.\n");
      goto fail;
    }
  if (res != LSH_HELLO_LINE_LENGTH)
    {
      werror ("Truncated hello message.\n");
      goto fail;
    }

  if (memcmp (lsh_string_data (buf), expected, sizeof(expected) - 1) != 0)
    {
      werror ("Invalid hello message.\n");
      goto fail;
    }
  lsh_string_free (buf);
  return 1;  
}

int
main(int argc, char **argv)
{
  struct client_connection *connection;
  struct lsh_options *options;
  int fd;
  
  /* Default exit code if something goes wrong. */
  int lsh_exit_code = 17;

  struct exception_handler *handler
    = make_lsh_default_handler(&lsh_exit_code, HANDLER_CONTEXT);

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

  env_parse(&main_argp, getenv(ENV_LSHFLAGS), ARGP_IN_ORDER, options);
  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);

  if (options->stop_gateway)
    {
      /* Stop any existing gateway. */
      static const uint8_t stop_message[] =
	{
	  0, 0, 0, 0,  /* seqno */
	  0, 0, 0, 1,  /* length */
	  SSH_LSH_GATEWAY_STOP,
	};

      fd = io_connect_local(options->gateway);
      if (fd < 0)
	{
	  werror("Could not open gateway: %e\n", errno);
	  if (!options->start_gateway)
	    return EXIT_FAILURE;
	}
      else
	{
	  if (!write_raw(fd, sizeof(stop_message), stop_message))
	    {
	      werror("Failed to send stop message to gateway.\n");
	      if (!options->start_gateway)
		return EXIT_FAILURE;
	    }
	  close(fd);
	}
      if (!options->start_gateway)
	return EXIT_SUCCESS;
    }

  fd = -1;

  if (options->use_gateway)
    {
      fd = io_connect_local(options->gateway);
      if (fd < 0)
	{
	  werror("Could not open gateway: %e\n", errno);
	  if (options->start_gateway < 0)
	    options->start_gateway = 1;
	}
    }

  if (fd < 0 && options->use_gateway != 1)
    fd = fork_lsh_transport(options);

  if (fd < 0)
    return EXIT_FAILURE;

  if (!process_hello_message (fd))
    return EXIT_FAILURE;

  connection = make_client_connection(fd);
  gc_global(&connection->super.super);

  if (options->start_gateway == 1)
    client_prepend_action(&options->super,
			  make_gateway_setup(options->gateway));

  /* Contains session channels to be opened. */
  remember_resource(connection->super.resources,
		    &options->super.resources->super);

  if (options->super.remote_forward)
    ALIST_SET(connection->super.channel_types, ATOM_FORWARDED_TCPIP,
	      &channel_open_forwarded_tcpip.super);


  while (!object_queue_is_empty(&options->super.actions))
    {
      CAST_SUBTYPE(command, action,
		   object_queue_remove_head(&options->super.actions));
	COMMAND_CALL(action, connection, &discard_continuation, handler);
    }
  
  io_run();
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  return lsh_exit_code;
}
