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

#include "lsh.c.x"

#define DEFAULT_ESCAPE_CHAR '~'
#define DEFAULT_SOCKS_PORT 1080

/* Flow control status: If the buffer for writing to the transport
   layer gets full, we stop reading on all channels, and we stop
   reading from all gateways. FIXME: Missing pieces:

   1. If a channel is somewhere in the opening handshake when we
      detect the transport buffer getting full, it is not signalled to
      stop, and might start generating data when the handshake is
      finished.

*/


/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel
 *
 * NOTE: Large windows seem to trig a bug in sshd2. */
#define WINDOW_SIZE 10000

/* GABA:
   (class
     (name lsh_options)
     (super werror_config)
     (vars
       (home . "const char *")

       ; -1 means default.
       (escape . int)
       
       (handler object exception_handler)

       (exit_code . "int *")

       (not . int)
       (port . "const char *")
       (target . "const char *")

       (local_user . "char *")
       (user . "char *")

       (with_remote_peers . int)
       
       ; -1 means default behaviour
       (with_pty . int)

       (with_x11 . int)
       
       ; Session modifiers
       (stdin_file . "const char *")
       (stdout_file . "const char *")
       (stderr_file . "const char *")

       ; True if the process's stdin or pty (respectively) has been used. 
       (used_stdin . int)
       (used_pty . int)

       ; Should -B write the pid to stdout?
       (write_pid . int)
       
       ; True if the client should detach when a session closes (useful for gateways)
       (detach_end . int)

       ; Inhibit actions, used to not create actions from environment parsing.
       (inhibit_actions . int)

       (start_shell . int)
       (remote_forward . int)
       (x11_forward . int)
       (actions struct object_queue)

       ; 0 means no, 1 means yes, -1 means use if available.
       (use_gateway . int)
       ; 0 means no, 1 means yes, -1 means start if not already available.
       (start_gateway . int)
       (stop_gateway . int)

       (gateway object local_info)

       (transport_args . "struct arglist")

       ; Resources that are created during argument parsing. These should be adopted
       ; by the connection once it is up and running.
       (resources object resource_list)))
*/


static struct lsh_options *
make_options(struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);
  const char *home = getenv(ENV_HOME);
  const char *transport_program;

  init_werror_config(&self->super);

  self->home = home;

  self->escape = -1;

  self->handler = handler;

  self->exit_code = exit_code;

  self->not = 0;
  self->port = NULL;
  self->target = NULL;

  USER_NAME_FROM_ENV(self->user);
  self->local_user = self->user;

  self->with_remote_peers = 0;
  self->with_pty = -1;
  self->with_x11 = 0;

  self->stdin_file = NULL;
  self->stdout_file = NULL;
  self->stderr_file = NULL;

  self->used_stdin = 0;
  self->used_pty = 0;

  self->detach_end = 0;
  self->write_pid = 0;

  self->start_shell = 1;
  self->x11_forward = 0;
  self->remote_forward = 0;

  self->inhibit_actions = 0;

  object_queue_init(&self->actions);

  self->use_gateway = -1;
  self->start_gateway = 0;
  self->stop_gateway = 0;
  self->gateway = NULL;

  arglist_init(&self->transport_args);

  /* Set argv[0] */
  GET_FILE_ENV(transport_program, LSH_TRANSPORT);
  arglist_push(&self->transport_args, transport_program);

  self->resources = make_resource_list();
  gc_global(&self->resources->super);

  return self;
}

static void
add_action(struct lsh_options *options,
	   struct command *action)
{
  assert(action);
  object_queue_add_tail(&options->actions, &action->super);
}

/* Create a session object. stdout and stderr are shared (although
 * with independent lsh_fd objects). stdin can be used by only one
 * session. */
static struct client_session *
make_client_session(struct lsh_options *options,
		    struct object_list *session_actions)
{
  int in;
  int out;
  int err;
  
  int is_tty = 0;
  struct client_session *session;
  
  struct escape_info *escape = NULL;
#if 0
  struct lsh_callback *detach_cb = NULL;
#endif
  debug("lsh.c: Setting up stdin\n");

  if (options->stdin_file)
    in = open(options->stdin_file, O_RDONLY);
      
  else
    {
      if (options->used_stdin)
	in = open("/dev/null", O_RDONLY);
      else 
	{
	  in = STDIN_FILENO;
	  is_tty = isatty(STDIN_FILENO);
	  
	  options->used_stdin = 1;
	}
    }

  if (in < 0)
    {
      werror("Can't open stdin %e\n", errno);
      return NULL;
    }

  /* Attach the escape char handler, if appropriate. */
  if (options->escape > 0)
    {
      verbose("Enabling explicit escape character `%pc'\n",
	      options->escape);
      escape = make_client_escape(options->escape);
    }
  else if ( (options->escape < 0) && is_tty)
    {
      verbose("Enabling default escape character `%pc'\n",
	      DEFAULT_ESCAPE_CHAR);
      escape = make_client_escape(DEFAULT_ESCAPE_CHAR);
    }
  
  debug("lsh.c: Setting up stdout\n");

  if (options->stdout_file)
    /* FIXME: Use O_TRUNC too? */
    out = open(options->stdout_file, O_WRONLY | O_CREAT, 0666);
  else
    out = STDOUT_FILENO;

  if (out < 0)
    {
      werror("Can't open stdout %e\n", errno);
      close(in);
      return NULL;
    }

  debug("lsh.c: Setting up stderr\n");
  
  if (options->stderr_file)
    /* FIXME: Use O_TRUNC too? */
    err = open(options->stderr_file, O_WRONLY | O_CREAT, 0666);
  else
    err = STDERR_FILENO;

  if (err < 0) 
    {
      werror("Can't open stderr!\n");
      return NULL;
    }

#if 0
  if (options->detach_end) /* Detach? */
    detach_cb = make_detach_callback(options->exit_code);  
#endif

  /* Clear options */
  options->stdin_file = options->stdout_file = options->stderr_file = NULL;

  session = make_client_session_channel(in, out, err,
					session_actions,
					options->handler,
					escape,
					WINDOW_SIZE,
					options->exit_code);
  
#if 0
  if (options->detach_end)
    {
      remember_resource(session->resources, make_detach_resource(detach_cb));
      options->detach_end = 0;
    }
#endif

  /* The channel won't get registered in anywhere else until later, so
   * we must register it here to be able to clean up properly if the
   * connection fails early. */
  remember_resource(options->resources, &session->super.super);
  
  return session;
}

static struct client_session_action *
maybe_pty(struct lsh_options *options, int default_pty)
{
#if WITH_PTY_SUPPORT
  int with_pty = options->with_pty;
  if (with_pty < 0)
    with_pty = default_pty;

  if (with_pty && !options->used_pty)
    {
      options->used_pty = 1;
      
      if (interact_is_tty())
	return &client_request_pty;
      else
	/* FIXME: Try allocating a remote pty even if we don't have a
	   pty locally? I think lsh-1.x and 2.x did that. */
	werror("No tty available.\n");
    }
#endif
  return NULL;
}

static struct client_session_action *
maybe_x11(struct lsh_options *options)
{  
  if (options->with_x11)
    {
      char *display = getenv(ENV_DISPLAY);
      struct client_session_action *action = NULL;

      if (display)
	action = make_x11_action(display);

      if (action)
	options->x11_forward = 1;
      else
	werror("Can't find any local X11 display to forward.\n");

      return action;
    }
  return NULL;
}

/* Create an interactive session */
static struct command *
client_shell_session(struct lsh_options *options)
{  
  struct client_session_action *pty = maybe_pty(options, 1);
  struct client_session_action *x11 = maybe_x11(options);
  struct object_list *session_actions = alloc_object_list(1 + !!pty + !!x11);
  unsigned i = 0;

  if (pty)
    LIST(session_actions)[i++] = &pty->super;
  if (x11)
    LIST(session_actions)[i++] = &x11->super;

  LIST(session_actions)[i++] = &client_request_shell.super;

  assert(i == LIST_LENGTH(session_actions));
  
  return make_open_session_command(
	   &make_client_session(options, session_actions)->super);
}

/* Create a session for a subsystem */
static struct command *
client_subsystem_session(struct lsh_options *options,
			 struct lsh_string *subsystem)
{
  struct object_list *session_actions
    = make_object_list(1, make_subsystem_action(subsystem),
		       -1);

  return make_open_session_command(
	   &make_client_session(options, session_actions)->super);
}

/* Create a session executing a command line */
static struct command *
client_command_session(struct lsh_options *options,
		       struct lsh_string *command)
{
  struct client_session_action *pty = maybe_pty(options, 0);
  struct client_session_action *x11 = maybe_x11(options);
  struct object_list *session_actions = alloc_object_list(1 + !!pty + !!x11);
  unsigned i = 0;

  if (pty)
    LIST(session_actions)[i++] = &pty->super;
  if (x11)
    LIST(session_actions)[i++] = &x11->super;

  LIST(session_actions)[i++] = &make_exec_action(command)->super;

  assert(i == LIST_LENGTH(session_actions));
  return make_open_session_command(
	   &make_client_session(options, session_actions)->super);
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

  OPT_STDIN,
  OPT_STDOUT,
  OPT_STDERR,
 
  OPT_SUBSYSTEM,
  OPT_DETACH,
 
  OPT_ASKPASS,
 
  OPT_WRITE_PID,

  OPT_USE_GATEWAY,
  OPT_START_GATEWAY,
  OPT_STOP_GATEWAY
};

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "port", 'p', "PORT", 0, "Connect to this port.", 0 },
  { "user", 'l', "NAME", 0, "Login as this user.", 0 },
  { "askpass", OPT_ASKPASS, "Program", 0,
    "Program to use for reading passwords. "
    "Should be an absolute filename.", 0 },
  { NULL, 0, NULL, 0, "Actions:", 0 },

  { "forward-local-port", 'L', "LOCAL-PORT:TARGET-HOST:TARGET-PORT", 0,
    "Forward TCP/IP connections at a local port", 0 },
  { "forward-socks", 'D', "PORT", OPTION_ARG_OPTIONAL, "Enable socks dynamic forwarding", 0 },
  /* FIXME: Remote forwarding and X11 forwarding doesn't work over a gateway. */
  { "forward-remote-port", 'R', "REMOTE-PORT:TARGET-HOST:TARGET-PORT", 0,
    "Forward TCP/IP connections at a remote port", 0 },
  { "nop", 'N', NULL, 0, "No operation (suppresses the default action, "
    "which is to spawn a remote shell)", 0 },
  { "background", 'B', NULL, 0, "Put process into the background. Implies -N.", 0 },
  { "execute", 'E', "COMMAND", 0, "Execute a command on the remote machine", 0 },
  { "shell", 'S', NULL, 0, "Spawn a remote shell", 0 },
  { "subsystem", OPT_SUBSYSTEM, "SUBSYSTEM-NAME", 0,
#if WITH_PTY_SUPPORT 
    "Connect to given subsystem. Implies --no-pty.",
#else
    "Connect to given subsystem.",
#endif
    0 },

  { NULL, 0, NULL, 0, "Universal not:", 0 },
  { "no", 'n', NULL, 0, "Inverts the effect of the next modifier", 0 },

  { NULL, 0, NULL, 0, "Modifiers that apply to port forwarding:", 0 },
  { "remote-peers", 'g', NULL, 0, "Allow remote access to forwarded ports", 0 },
  { "no-remote-peers", 'g' | ARG_NOT, NULL, 0, 
    "Disallow remote access to forwarded ports (default).", 0 },

  { NULL, 0, NULL, 0, "Modifiers that apply to remote execution:", 0 },
  { "stdin", OPT_STDIN, "Filename", 0, "Redirect stdin", 0},
  { "no-stdin", OPT_STDIN | ARG_NOT, NULL, 0, "Redirect stdin from /dev/null", 0}, 
  { "stdout", OPT_STDOUT, "Filename", 0, "Redirect stdout", 0},
  { "no-stdout", OPT_STDOUT | ARG_NOT, NULL, 0, "Redirect stdout to /dev/null", 0}, 
  { "stderr", OPT_STDERR, "Filename", 0, "Redirect stderr", 0},
  { "no-stderr", OPT_STDERR | ARG_NOT, NULL, 0, "Redirect stderr to /dev/null", 0}, 

  { "detach", OPT_DETACH, NULL, 0, "Detach from terminal at session end.", 0},
  { "no-detach", OPT_DETACH | ARG_NOT, NULL, 0, "Do not detach session at end," 
    " wait for all open channels (default).", 0},

#if WITH_PTY_SUPPORT
  { "pty", 't', NULL, 0, "Request a remote pty (default).", 0 },
  { "no-pty", 't' | ARG_NOT, NULL, 0, "Don't request a remote pty.", 0 },
#endif /* WITH_PTY_SUPPORT */
#if WITH_X11_FORWARD
  { "x11-forward", 'x', NULL, 0, "Enable X11 forwarding.", 0 },
  { "no-x11-forward", 'x' | ARG_NOT, NULL, 0,
    "Disable X11 forwarding (default).", 0 },
#endif

  { NULL, 0, NULL, 0, "Miscellaneous options:", 0 },
  { "escape-char", 'e', "Character", 0, "Escape char. `none' means disable. "
    "Default is to use `~' if we have a tty, otherwise none.", 0 },
  { "write-pid", OPT_WRITE_PID, NULL, 0, "Make -B write the pid of the backgrounded "
    "process to stdout.", 0 },

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
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static int
parse_arg_unsigned(const char *arg, unsigned long *n)
{
  char *end;
  if (*arg == 0)
    return 0;

  *n = strtoul(arg, &end, 0);
  return *end == 0;
}

/* Parse the argument for -R and -L */
static int
parse_forward_arg(char *arg,
		  unsigned long *listen_port,
		  struct address_info **target)
{
  const char *host;
  const char *target_port;
  char *sep;
  
  sep = strchr(arg, ':');
  if (!sep)
    return 0;

  sep[0] = '\0';

  if (!parse_arg_unsigned(arg, listen_port))
    return 0;
  
  host = sep + 1;

  sep = strchr(host, ':');
  if (!sep)
    return 0;

  sep[0] = '\0';
  target_port = sep + 1;

  *target = io_lookup_address(host, target_port);
  
  return *target != NULL;
}

#define CASE_ARG(opt, attr, none)		\
  case opt:					\
    if (self->not)				\
      {						\
        self->not = 0;				\
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
    if (self->not)				\
      {						\
        self->not = 0;				\
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
      
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!state->arg_num)
	self->target = arg;
      
      else
	/* Let the next case parse it.  */
	return ARGP_ERR_UNKNOWN;

      break;
    case ARGP_KEY_ARGS:
      add_action
	(self,
	 client_command_session
	 (self, client_rebuild_command_line(state->argc - state->next,
					    state->argv + state->next)));
      self->start_shell = 0;
      break;
    case ARGP_KEY_END:
      if (self->inhibit_actions)
	break;

      if (!werror_init(&self->super))
	argp_failure(state, EXIT_FAILURE, errno, "Failed to open log file");

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
       * remote machine (self->remote) first.
       */

      if (self->start_gateway || self->stop_gateway || self->use_gateway)
	{
	  if (!self->local_user)
	    {
	      argp_error(state, "You have to set LOGNAME in the environment, "
			 " if you want to use the gateway feature.");
	      break;
	    }
	  self->gateway = make_gateway_address(self->local_user,
					       self->user,
					       self->target);

	  if (!self->gateway)
	    {
	      argp_error(state, "Local or remote user name, or the target host name, are too "
			 "strange for the gateway socket name construction.");
	      break;
	    }
	}

      /* Add shell action */
      if (self->start_shell)
	add_action(self, client_shell_session(self));

      if (object_queue_is_empty(&self->actions) && !self->stop_gateway)
	{
	  argp_error(state, "No actions given.");
	  break;
	}

      break;

    case 'p':
      self->port = arg;
      break;

    case 'l':
      self->user = arg;
      break;

    case OPT_ASKPASS:
      arglist_push(&self->transport_args, "--askpass");
      arglist_push(&self->transport_args, arg);
      
      interact_set_askpass(arg);      
      break;
      
    case 'e':
      if (arg[0] && !arg[1])
	/* A single char argument */
	self->escape = arg[0];
      else if (!strcasecmp(arg, "none"))
	self->escape = 0;
      else
	argp_error(state, "Invalid escape char: `%s'. "
		   "You must use a single character or `none'.", arg);
      break;

    case 'E':
      add_action(self,
		 client_command_session(self,
					ssh_format("%lz", arg)));
      break;

    case 'S':
      add_action(self, client_shell_session(self));
      break;

    case OPT_SUBSYSTEM:
      add_action(self, client_subsystem_session(self,
						ssh_format("%lz", arg)));

      self->start_shell = 0;
#if WITH_PTY_SUPPORT
      self->with_pty = 0;
#endif
      break;

    case 'L':
      {
	unsigned long listen_port;
	struct address_info *target;

	if (!parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification `%s'.", arg);

	add_action(self, forward_local_port
		   (make_address_info((self->with_remote_peers
				       ? NULL
				       : ssh_format("%lz", "127.0.0.1")),
				      listen_port),
		    target));
	break;
      }      

    case 'D':
      {
	unsigned long socks_port = DEFAULT_SOCKS_PORT;
	if (arg && (parse_arg_unsigned(arg, &socks_port) == 0 || socks_port > 0xffff))
	  argp_error(state, "Invalid port number `%s' for socks.", arg);

	add_action(self, make_socks_server
		   (make_address_info((self->with_remote_peers
				       ? NULL
				       : ssh_format("%lz", "127.0.0.1")),
				      socks_port)));
	break;
      }

    case 'N':
      self->start_shell = 0;
      break;

    case 'B':
      self->start_shell = 0;
      add_action(self, make_background_process(self->write_pid));
      break;

      /* FIXME: Doesn't yet work over the gateway. */
    case 'R':
      {
	unsigned long listen_port;
	struct address_info *target;

	if (!parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	add_action(self, forward_remote_port
		   (make_address_info((self->with_remote_peers
				       ? ssh_format("%lz", "0.0.0.0")
				       : ssh_format("%lz", "127.0.0.1")),
				      listen_port),
		    target));

	self->remote_forward = 1;
	break;
      }

    CASE_FLAG('g', with_remote_peers);

#if WITH_PTY_SUPPORT
    CASE_FLAG('t', with_pty);
#endif /* WITH_PTY_SUPPORT */

#if WITH_X11_FORWARD
    CASE_FLAG('x', with_x11);
#endif

    CASE_FLAG(OPT_DETACH, detach_end);
    CASE_FLAG(OPT_WRITE_PID, write_pid);
    
    CASE_ARG(OPT_STDIN, stdin_file, "/dev/null");
    CASE_ARG(OPT_STDOUT, stdout_file, "/dev/null"); 
    CASE_ARG(OPT_STDERR, stderr_file, "/dev/null");

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

    case 'n':
      self->not = !self->not;
      break;

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
      arglist_push(&options->transport_args, options->user);

      if (options->super.verbose > 0)
	arglist_push(&options->transport_args, "-v");
      if (options->super.quiet > 0)
	arglist_push(&options->transport_args, "-q");	
      if (options->super.debug > 0)
	arglist_push(&options->transport_args, "--debug");
      if (options->super.trace > 0)
	arglist_push(&options->transport_args, "--trace");

      if (options->port)
	{
	  arglist_push(&options->transport_args, "-p");
	  arglist_push(&options->transport_args, options->port);
	}
      arglist_push(&options->transport_args, options->target);
      
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

  if (!unix_interact_init(1))
    return EXIT_FAILURE;

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

  options->inhibit_actions = 1; /* Disable normal actions performed at end */
  env_parse(&main_argp, getenv(ENV_LSHFLAGS), ARGP_IN_ORDER, options);
  options->inhibit_actions = 0; /* Reenable */

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
    {
      struct resource *port = make_gateway_port(options->gateway, connection);
      if (port)
	remember_resource(connection->super.resources, port);
      else
	werror("Failed to setup gateway.\n");
    }
  
  /* Contains session channels to be opened. */
  remember_resource(connection->super.resources,
		    &options->resources->super);

#if WITH_TCP_FORWARD
  if (options->remote_forward)
    ALIST_SET(connection->super.channel_types, ATOM_FORWARDED_TCPIP,
	      &channel_open_forwarded_tcpip.super);
#endif

#if WITH_X11_FORWARD
  if (options->x11_forward)
    ALIST_SET(connection->super.channel_types, ATOM_X11,
	      &channel_open_x11.super);
#endif

  while (!object_queue_is_empty(&options->actions))
    {
      CAST_SUBTYPE(command, action,
		   object_queue_remove_head(&options->actions));
	COMMAND_CALL(action, connection, &discard_continuation, handler);
    }
  
  io_run();
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  return lsh_exit_code;
}
