/* client.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000 Niels Möller
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

#include <fcntl.h>
#include <signal.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "client.h"

#include "channel.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "lsh_string.h"
#include "parse.h"
#include "ssh.h"
#include "suspend.h"
#include "tcpforward.h"
#include "translate_signal.h"
#include "xalloc.h"
#include "io.h"

#include "lsh_argp.h"

#define GABA_DEFINE
#include "client.h.x"
#undef GABA_DEFINE

struct command_2 open_session_command;
#define OPEN_SESSION (&open_session_command.super.super)

#include "client.c.x"

#define DEFAULT_ESCAPE_CHAR '~'
#define DEFAULT_SOCKS_PORT 1080

#if 0
/* ;; GABA:
   (class
     (name detach_callback)
     (super lsh_callback)
     (vars 
       (channel_flag . int)
       (fd_flag . int)
       (exit_status . "int *")))
*/

/* ;; GABA:
   (class
     (name detach_resource)
     (super resource)
     (vars
       (c object detach_callback)))
*/

static void 
do_detach_res_kill(struct resource *r)
{
  CAST(detach_resource,self,r);

  trace("client.c:do_detach_res\n");
  self->c->channel_flag = 1;

  if (self->c->channel_flag && self->c->fd_flag)
    /* If the fd_flag is set, the callback should be changed */
    io_callout(&self->c->super, 0);
}

static struct resource*
make_detach_resource(struct lsh_callback *c)
{
   NEW(detach_resource, self);
   CAST(detach_callback, cb, c);

   trace("client.c:make_detach_resource\n");
   init_resource(&self->super, do_detach_res_kill);

   self->c = cb;

   return &self->super;
}


static void 
do_detach_cb(struct lsh_callback *c)
{
  CAST(detach_callback,self,c);

  trace("client.c: do_detach_cb\n");
  
  if (!self->fd_flag) /* First time around? */
    {
      self->fd_flag = 1; /* Note */
      
      if (self->channel_flag && self->fd_flag)
	/* If the fd is closed already, ask to be called from the main loop */ 
	io_callout(c, 0);
    }
  else
    {
      int pid = fork();

      /* Ignore any errors, what can we do? */
      
      switch(pid)
	{
	case -1: /* Fork failed, this we can handle by doing nothing */
	  werror("Fork failed, not detaching.\n");
	  break;
	  
	case 0:
	  /* Detach */	  
	  close(STDIN_FILENO); 
	  close(STDOUT_FILENO); 
	  close(STDERR_FILENO); 
	  
	  /* Make sure they aren't used by any file lsh opens */
	  
	  open("/dev/null", O_RDONLY);
	  open("/dev/null", O_RDONLY);
	  open("/dev/null", O_RDONLY);
	  break;
	  
	default:
	  exit(*self->exit_status);
	}
    }
}

static struct lsh_callback* 
make_detach_callback(int *exit_status)
{
   NEW(detach_callback, self);

   self->super.f = do_detach_cb;
   self->exit_status = exit_status;
   self->fd_flag = 0;
   self->channel_flag = 0;

   return &self->super;
}
#endif

/* FIXME: Move to client_session.c? */
/* GABA:
   (class
     (name exit_handler)
     (super channel_request)
     (vars
       (exit_status . "int *")))
*/

static void
do_exit_status(struct channel_request *s,
	       struct ssh_channel *channel,
	       const struct channel_request_info *info,
	       struct simple_buffer *args,
	       struct command_continuation *c,
	       struct exception_handler *e UNUSED)
{
  CAST(exit_handler, self, s);
  uint32_t status;

  if (!info->want_reply
      && parse_uint32(args, &status)
      && parse_eod(args))
    {
      verbose("client.c: Receiving exit-status %i on channel %i\n",
	      status, channel->remote_channel_number);

      *self->exit_status = status;
      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      assert(channel->sinks);
      channel->sinks--;
      channel_maybe_close(channel);

      COMMAND_RETURN(c, channel);
    }
  else
    /* Invalid request */
    SSH_CONNECTION_ERROR(channel->connection, "Invalid exit-status message");
}

static void
do_exit_signal(struct channel_request *s,
	       struct ssh_channel *channel,
	       const struct channel_request_info *info,
	       struct simple_buffer *args,
	       struct command_continuation *c,
	       struct exception_handler *e UNUSED)
{
  CAST(exit_handler, self, s);

  enum lsh_atom signal;
  int core;

  const uint8_t *msg;
  uint32_t length;

  const uint8_t *language;
  uint32_t language_length;
  
  if (!info->want_reply
      && parse_atom(args, &signal)
      && parse_boolean(args, &core)
      && parse_string(args, &length, &msg)
      && parse_string(args, &language_length, &language)
      && parse_eod(args))
    {
      /* FIXME: What exit status should be returned when the remote
       * process dies violently? */

      *self->exit_status = 7;

      werror("Remote process was killed by signal: %ups %z\n",
	     length, msg,
	     core ? "(core dumped remotely)\n": "");
      
      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      assert(channel->sinks);
      channel->sinks--;
      channel_maybe_close(channel);

      COMMAND_RETURN(c, channel);
    }
  else
    /* Invalid request */
    SSH_CONNECTION_ERROR(channel->connection, "Invalid exit-signal message");
}

struct channel_request *
make_handle_exit_status(int *exit_status)
{
  NEW(exit_handler, self);

  self->super.handler = do_exit_status;

  self->exit_status = exit_status;

  return &self->super;
}

struct channel_request *
make_handle_exit_signal(int *exit_status)
{
  NEW(exit_handler, self);

  self->super.handler = do_exit_signal;

  self->exit_status = exit_status;

  return &self->super;
}


/* GABA:
   (class
     (name session_open_command)
     (super command)
     (vars
       ; This command can only be executed once,
       ; so we can allocate the session object in advance.
       (channel object ssh_channel)))
*/

static void
do_open_session_command(struct command *s,
			struct lsh_object *a,
			struct command_continuation *c UNUSED,
			struct exception_handler *e)
{
  CAST(session_open_command, self, s);
  CAST_SUBTYPE(ssh_connection, connection, a);
  
  if (!channel_open_new_type(connection, self->channel,
			     ATOM_LD(ATOM_SESSION), ""))
    {
      EXCEPTION_RAISE(e, make_exception(EXC_CHANNEL_OPEN, SSH_OPEN_RESOURCE_SHORTAGE,
					"Allocating a local channel number failed."));
      KILL_RESOURCE(&self->channel->super);
    }
}

struct command *
make_open_session_command(struct ssh_channel *channel)
{
  NEW(session_open_command, self);
  self->super.call = do_open_session_command;
  self->channel = channel;

  return &self->super;
}

DEFINE_COMMAND(request_shell)
     (struct command *s UNUSED,
      struct lsh_object *x,
      struct command_continuation *c UNUSED,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(ssh_channel, channel, x);

  channel_send_request(channel, ATOM_SHELL, 1, NULL, "");
}

/* Used for both exec and subsystem request. */
/* GABA:
   (class
     (name session_channel_request)
     (super command)
     (vars
       (type . int)
       (arg string)))
*/

static void
do_session_channel_request(struct command *s,
			   struct lsh_object *x,
			   struct command_continuation *c UNUSED,
			   struct exception_handler *e UNUSED)
{
  CAST(session_channel_request, self, s);
  CAST_SUBTYPE(ssh_channel, channel, x);

  verbose("Requesting remote %a.\n", self->type);

  channel_send_request(channel, self->type, 1, NULL,
		       "%S", self->arg);
}

struct command *
make_session_channel_request(int type, struct lsh_string *arg)
{
  NEW(session_channel_request, self);

  self->super.call = do_session_channel_request;
  self->type = type;
  self->arg = arg;

  return &self->super;
}

struct command *
make_exec_request(struct lsh_string *command)
{
  return make_session_channel_request(ATOM_EXEC, command);
}

struct command *
make_subsystem_request(struct lsh_string *subsystem)
{
  return make_session_channel_request(ATOM_SUBSYSTEM, subsystem);
}


/* Handling of options and operations shared by the plain lsh client
 * and lshg. */

/* Forward declaration */

static struct client_session *
make_client_session(struct client_options *options);

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel
 *
 * NOTE: Large windows seem to trig a bug in sshd2. */
#define WINDOW_SIZE 10000

#define ARG_NOT 0x400

#define OPT_STDIN 0x210
#define OPT_STDOUT 0x211
#define OPT_STDERR 0x212

#define OPT_SUBSYSTEM 0x214
#define OPT_DETACH 0x215

#define OPT_ASKPASS 0x216

#define OPT_WRITE_PID 0x217

void
init_client_options(struct client_options *self,
		    struct randomness *random,
		    struct exception_handler *handler,
		    int *exit_code)			 
{
  init_werror_config(&self->super);

  self->random = random;

  self->tty = make_unix_interact();
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
  self->used_x11 = 0;
  
  self->detach_end = 0;
  self->write_pid = 0;
  
  self->start_shell = 1;
  self->remote_forward = 0;

  self->inhibit_actions = 0;

  object_queue_init(&self->actions);
  
  self->resources = make_resource_list();
  gc_global(&self->resources->super);
}

static const struct argp_option
client_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "port", 'p', "PORT", 0, "Connect to this port.", 0 },
  { "user", 'l', "NAME", 0, "Login as this user.", 0 },
  { "askpass", OPT_ASKPASS, "Program", 0,
    "Program to use for reading passwords. "
    "Should be an absolute filename.", 0 },
  { NULL, 0, NULL, 0, "Actions:", CLIENT_ARGP_ACTION_GROUP },

  { "forward-local-port", 'L', "LOCAL-PORT:TARGET-HOST:TARGET-PORT", 0,
    "Forward TCP/IP connections at a local port", 0 },
  { "forward-socks", 'D', "PORT", OPTION_ARG_OPTIONAL, "Enable socks dynamic forwarding", 0 },
#if 0
  { "forward-remote-port", 'R', "REMOTE-PORT:TARGET-HOST:TARGET-PORT", 0, "", 0 },
#endif
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

  { NULL, 0, NULL, 0, "Modifiers that apply to port forwarding:",
    CLIENT_ARGP_MODIFIER_GROUP - 10 },
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
  { NULL, 0, NULL, 0, "Miscellaneous options:", 0 },
  { "escape-char", 'e', "Character", 0, "Escape char. `none' means disable. "
    "Default is to use `~' if we have a tty, otherwise none.", 0 },
  { "write-pid", OPT_WRITE_PID, NULL, 0, "Make -B write the pid of the backgrounded "
    "process to stdout.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static void
client_maybe_pty(struct client_options *options,
		 int default_pty,
		 struct object_queue *q)
{
#if WITH_PTY_SUPPORT
  int with_pty = options->with_pty;
  if (with_pty < 0)
    with_pty = default_pty;

  if (with_pty && !options->used_pty)
    {
      options->used_pty = 1;
      
      if (options->tty && INTERACT_IS_TTY(options->tty))
	{
	  struct command *get_pty = make_pty_request(options->tty);

	  if (get_pty)
	    object_queue_add_tail(q, &get_pty->super);
	  else
	    werror("Can't use tty (probably getattr or atexit failed).\n");
	}
      else
	/* FIXME: Try allocating a remote pty even if we don't have a
	   pty locally? I think lsh.x and 2.x did that. */
	werror("No tty available.\n");
    }
#endif
}

static void
client_maybe_x11(struct client_options *options,
		 struct object_queue *q)
{
#if 0
  if (options->with_x11)
    {
      char *display = getenv(ENV_DISPLAY);
      struct command *request = NULL;
      
      assert(options->random);
      if (display)
	request = make_forward_x11(display, options->random);
	  
      if (request)
	{
	  object_queue_add_tail(q, &request->super);
	  options->used_x11 = 1;
	}
      else
	werror("Can't find any local X11 display to forward.\n");
    }
#endif
}

/* Create an interactive session */
static struct command *
client_shell_session(struct client_options *options)
{
  struct client_session *session = make_client_session(options);

  if (session)
    {
      client_maybe_pty(options, 1, &session->requests);
      client_maybe_x11(options, &session->requests);
  
      object_queue_add_tail(&session->requests, &request_shell.super);

      return make_open_session_command(&session->super);
    }
  else
    return NULL;
}

/* Create a session for a subsystem */
static struct command *
client_subsystem_session(struct client_options *options,
			 struct lsh_string *subsystem)
{
  struct client_session *session = make_client_session(options);

  if (session)
    {
      object_queue_add_tail(&session->requests,
			    &make_subsystem_request(subsystem)->super);
      return make_open_session_command(&session->super);
    }
  else
    return NULL;
}

/* Create a session executing a command line */
static struct command *
client_command_session(struct client_options *options,
		       struct lsh_string *command)
{
  struct client_session *session = make_client_session(options);

  if (session)
    {
      /* NOTE: Doesn't ask for a pty by default. That's traditional
       * behaviour, although perhaps not the Right Thing. */

      client_maybe_pty(options, 0, &session->requests);
      client_maybe_x11(options, &session->requests);

      object_queue_add_tail(&session->requests,
			    &make_exec_request(command)->super);
      return make_open_session_command(&session->super);
    }
  else
    return NULL;
}

struct command *
client_add_action(struct client_options *options,
		  struct command *action)
{
  if (action)
    object_queue_add_tail(&options->actions, &action->super);

  return action;
}

struct command *
client_prepend_action(struct client_options *options,
		      struct command *action)
{
  if (action)
    object_queue_add_head(&options->actions, &action->super);

  return action;
}

/* NOTE: Some of the original quoting is lost here. */
static struct lsh_string *
rebuild_command_line(unsigned argc, char **argv)
{
  unsigned length;
  unsigned i;
  unsigned pos;
  struct lsh_string *r;
  unsigned *alengths = alloca(sizeof(unsigned) * argc);
  
  assert (argc);
  length = argc - 1; /* Number of separating spaces. */

  for (i = 0; i<argc; i++)
    {
      alengths[i] = strlen(argv[i]);
      length += alengths[i];
    }

  r = lsh_string_alloc(length);
  lsh_string_write(r, 0, alengths[0], argv[0]);
  pos = alengths[0];
  for (i = 1; i<argc; i++)
    {
      lsh_string_putc(r, pos++, ' ');
      lsh_string_write(r, pos, alengths[i], argv[i]);
      pos += alengths[i];
    }

  assert(pos == length);

  return r;
}

/* A callback that exits the process immediately. */
DEFINE_ESCAPE(exit_callback, "Exit.")
{
  exit(EXIT_SUCCESS);
}

DEFINE_ESCAPE(quiet_callback, "Toggle warning messages.")
{
  toggle_quiet();
}

DEFINE_ESCAPE(verbose_callback, "Toggle verbose messages.")
{
  toggle_verbose();
}

DEFINE_ESCAPE(trace_callback, "Toggle trace messages.")
{
  toggle_trace();
}

DEFINE_ESCAPE(debug_callback, "Toggle trace messages.")
{
  toggle_trace();
}

/* GABA:
   (class
     (name background_process_command)
     (super command)
     (vars
       (write_pid . int)))
*/

static void
do_background_process(struct command *s,
		      struct lsh_object *a,
		      struct command_continuation *c,
		      struct exception_handler *e UNUSED)
{
  CAST(background_process_command, self, s);
  pid_t pid;
  
  trace("do_background_process\n");
  
  pid = fork();
  
  switch (pid)
    {
    case 0:
      /* Child */
      /* FIXME: Should we create a new process group, close our tty
       * and stdio, etc? */
      COMMAND_RETURN(c, a);
      break;
    case -1:
      /* Error */
      werror("background_process: fork failed %e\n", errno);
      COMMAND_RETURN(c, a);
      break;
    default:
      /* Parent */
      if (self->write_pid)
	{
	  struct lsh_string *msg = ssh_format("%di\n", pid);
	  if (!write_raw (STDOUT_FILENO, STRING_LD(msg)))
	    werror ("Write to stdout failed!?: %e\n", errno);
	}
      _exit(EXIT_SUCCESS);
    }
}

static struct command *
make_background_process(int write_pid)
{
  NEW(background_process_command, self);

  self->super.call = do_background_process;
  self->write_pid = write_pid;

  return &self->super;
}

/* Create a session object. stdout and stderr are shared (although
 * with independent lsh_fd objects). stdin can be used by only one
 * session (until something "session-control"/"job-control" is added).
 * */
static struct client_session *
make_client_session(struct client_options *options)
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
      escape = make_escape_info(options->escape);
    }
  else if ( (options->escape < 0) && is_tty)
    {
      verbose("Enabling default escape character `%pc'\n",
	      DEFAULT_ESCAPE_CHAR);
      escape = make_escape_info(DEFAULT_ESCAPE_CHAR);
    }

  /* Bind ^Z to suspend. */
  if (escape)
    {
      /* Bind ^Z to suspend. */
      escape->dispatch[26] = &suspend_callback;
      escape->dispatch['.'] = &exit_callback;

      /* Toggle the verbosity flags */
      escape->dispatch['q'] = &quiet_callback;      
      escape->dispatch['v'] = &verbose_callback;
      escape->dispatch['t'] = &trace_callback;
      escape->dispatch['d'] = &debug_callback;
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


/* Treat environment variables as sources for options */

/* FIXME: Can we obsolete this hack once we have reasonable
   configuration files? */
void
env_parse(const struct argp *argp,
	  const char *value,
	  unsigned flags, 
	  void *input)
{
  CAST_SUBTYPE(client_options, options, input);

  if (value)
    {
      char **sim_argv;
      char *entry;

      /* Make a copy we can modify */
      entry = strdup(value);

      if (entry)
	{
	  /* Extra space doesn't hurt */
	  sim_argv = malloc(sizeof(char*) * (strlen(entry)+2));

	  if (sim_argv)
	    {
	      int sim_argc = 1;
	      char *token = strtok(entry, " \n\t");
		  
	      sim_argv[0] = "";

	      while (token) /* For all tokens in variable */
		{
		  sim_argv[sim_argc++] = token;
		  token = strtok( NULL, " \n\t");
		}

	      sim_argv[sim_argc] = NULL;
	
	      options->inhibit_actions = 1; /* Disable nnormal actions performed at end */
	      argp_parse(argp, sim_argc, sim_argv, flags | ARGP_NO_ERRS | ARGP_NO_EXIT, NULL, input);
	      options->inhibit_actions = 0; /* Reenable */
	    }
	  free(entry);
	}
    }
}

static int
client_arg_unsigned(const char *arg, unsigned long *n)
{
  char *end;
  if (*arg == 0)
    return 0;

  *n = strtoul(arg, &end, 0);
  return *end == 0;
}

/* Parse the argument for -R and -L */
int
client_parse_forward_arg(char *arg,
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

  if (!client_arg_unsigned(arg, listen_port))
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
    if (options->not)				\
      {						\
        options->not = 0;			\
						\
      case opt | ARG_NOT:			\
        options->attr = none;			\
        break;					\
      }						\
      						\
    options->attr = arg;			\
    break

#define CASE_FLAG(opt, flag)			\
  case opt:					\
    if (options->not)				\
      {						\
        options->not = 0;			\
						\
      case opt | ARG_NOT:			\
        options->flag = 0;			\
        break;					\
      }						\
      						\
    options->flag = 1;				\
    break

static error_t
client_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST_SUBTYPE(client_options, options, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &options->super;
      break;
      
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!state->arg_num)
	options->target = arg;
      
      else
	/* Let the next case parse it.  */
	return ARGP_ERR_UNKNOWN;

      break;
    case ARGP_KEY_ARGS:
      client_add_action
	(options,
	 client_command_session
	 (options, rebuild_command_line(state->argc - state->next,
				     state->argv + state->next)));
      options->start_shell = 0;
      break;

    case ARGP_KEY_END:
      if (!werror_init(&options->super))
	argp_failure(state, EXIT_FAILURE, errno, "Failed to open log file");

      if (options->inhibit_actions)
	break;

      if (!options->user)
	{
	  argp_error(state, "No user name given. Use the -l option, or set LOGNAME in the environment.");
	  break;
	}

#if 0
#if WITH_TCP_FORWARD
      if (options->remote_forward)
	client_add_action(options,
			  make_install_fix_channel_open_handler
			  (ATOM_FORWARDED_TCPIP, &channel_open_forwarded_tcpip));
#endif /* WITH_TCP_FORWARD */
#endif
      /* Add shell action */
      if (options->start_shell)
	client_add_action(options, client_shell_session(options));

#if 0
      if (options->used_x11)
	client_add_action(options,
			  make_install_fix_channel_open_handler
			  (ATOM_X11,
			   &channel_open_x11));
#endif 
      /* Install suspend-handler */
      suspend_install_handler();
      break;

    case 'p':
      options->port = arg;
      break;

    case 'l':
      options->user = arg;
      break;

    case OPT_ASKPASS:
      INTERACT_SET_ASKPASS(options->tty, arg);
      break;
      
    case 'e':
      if (arg[0] && !arg[1])
	/* A single char argument */
	options->escape = arg[0];
      else if (!strcasecmp(arg, "none"))
	options->escape = 0;
      else
	argp_error(state, "Invalid escape char: `%s'. "
		   "You must use a single character or `none'.", arg);
      break;
    case 'E':
      client_add_action(options,
			client_command_session(options,
					       ssh_format("%lz", arg)));
      break;

    case 'S':
      client_add_action(options, client_shell_session(options));
      break;

    case OPT_SUBSYSTEM:
      client_add_action(options,
			client_subsystem_session(options,
						 ssh_format("%lz", arg)));

      options->start_shell = 0;
#if WITH_PTY_SUPPORT
      options->with_pty = 0;
#endif
      break;

    case 'L':
      {
	unsigned long listen_port;
	struct address_info *target;

	if (!client_parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification `%s'.", arg);

	client_add_action(options, forward_local_port
			  (make_address_info((options->with_remote_peers
					      ? NULL
					      : ssh_format("%lz", "127.0.0.1")),
					     listen_port),
			   target));
	break;
      }      

    case 'D':
      {
	unsigned long socks_port = DEFAULT_SOCKS_PORT;
	if (arg && (client_arg_unsigned(arg, &socks_port) == 0 || socks_port > 0xffff))
	  argp_error(state, "Invalid port number `%s' for socks.", arg);

	client_add_action(options, make_socks_server
			  (make_address_info((options->with_remote_peers
					      ? NULL
					      : ssh_format("%lz", "127.0.0.1")),
					     socks_port)));
	break;
      }

    case 'N':
      options->start_shell = 0;
      break;

    case 'B':
      options->start_shell = 0;
      client_add_action(options, make_background_process(options->write_pid));
      break;
      
    CASE_FLAG('g', with_remote_peers);

#if WITH_PTY_SUPPORT
    CASE_FLAG('t', with_pty);
#endif /* WITH_PTY_SUPPORT */

    CASE_FLAG(OPT_DETACH, detach_end);
    CASE_FLAG(OPT_WRITE_PID, write_pid);
    
    CASE_ARG(OPT_STDIN, stdin_file, "/dev/null");
    CASE_ARG(OPT_STDOUT, stdout_file, "/dev/null"); 
    CASE_ARG(OPT_STDERR, stderr_file, "/dev/null");

    case 'n':
      options->not = !options->not;
      break;
    }
  return 0;
}

static const struct argp_child
client_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};
  
const struct argp client_argp =
{
  client_options,
  client_argp_parser,
  NULL, NULL,
  client_argp_children,
  NULL, NULL
};
