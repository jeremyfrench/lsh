/* server_session.c
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "server_session.h"

#include "channel_commands.h"
#include "format.h"
#include "read_data.h"
#include "reaper.h"
#include "server_pty.h"
#include "ssh.h"
#include "tcpforward.h"
#include "translate_signal.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include <errno.h>

/* For debug */

#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <signal.h>

#include "server_session.c.x"


/* Session */
/* GABA:
   (class
     (name server_session)
     (super ssh_channel)
     (vars
       ; User information
       ;; (user object lsh_user)

       (initial_window . UINT32)

       ; Resource to kill when the channel is closed. 
       (process object lsh_process)

       ; pty
       (pty object pty_info)
       ; value of the TERM environment variable
       (term string)

       ; Child process's stdio 
       (in object lsh_fd)
       (out object lsh_fd)

       ; err may be NULL, if there's no separate stderr channel.
       ; This happens if we use a pty, and the bash workaround is used.
       (err object lsh_fd)))
*/

/* Receive channel data */
static void
do_receive(struct ssh_channel *c,
	   int type, struct lsh_string *data)
{
  CAST(server_session, closure, c);

  switch(type)
    {
    case CHANNEL_DATA:
      A_WRITE(&closure->in->write_buffer->super, data);
      break;
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      break;
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static void
do_send_adjust(struct ssh_channel *s,
	       UINT32 i UNUSED)
{
  CAST(server_session, session, s);

  /* FIXME: Perhaps it's better to just check the read pointers, and
   * not bother with the alive-flags? */
  if (session->out->super.alive)
    {
      assert(session->out->read);

      lsh_oop_register_read_fd(session->out);
    }
  
  if (session->err && session->err->super.alive)
    {
      assert(session->err->read);
  
      lsh_oop_register_read_fd(session->err);
    }
}

static void
do_eof(struct ssh_channel *channel)
{
  CAST(server_session, session, channel);

  trace("server_session.c: do_eof\n");

  if (session->pty)
    /* Is there any better way to signal EOF on a pty? This is what
     * emacs does. */
    /* FIXME: This should be handled specially by close_fd_write, so
     * that we can ignore EPIPE errors. */
    A_WRITE(&session->in->write_buffer->super,
            ssh_format("%lc", /* C-d */ 4));

  close_fd_write(session->in);
}

struct ssh_channel *
make_server_session(UINT32 initial_window,
		    struct alist *request_types)
{
  NEW(server_session, self);

  init_channel(&self->super);

  self->initial_window = initial_window;

  /* We don't want to receive any data before we have forked some
   * process to receive it. */
  self->super.rec_window_size = 0;

  /* FIXME: Make maximum packet size configurable. */
  self->super.rec_max_packet = SSH_MAX_PACKET - SSH_CHANNEL_MAX_PACKET_FUZZ;
  self->super.request_types = request_types;

  /* Note: We don't need a close handler; the channels resource list
   * is taken care of automatically. */
  
  self->process = NULL;
  
  self->in = NULL;
  self->out = NULL;
  self->err = NULL;
  
  return &self->super;
}


/* GABA:
   (class
     (name open_session)
     (super channel_open)
     (vars
       (session_requests object alist)))
*/

#define WINDOW_SIZE 10000

static void
do_open_session(struct channel_open *s,
		struct ssh_connection *connection UNUSED,
		struct channel_open_info *info UNUSED,
		struct simple_buffer *args,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(open_session, self, s);

  debug("server.c: do_open_session\n");

  assert(connection->user);
  
  if (parse_eod(args))
    {
      COMMAND_RETURN(c,
		     make_server_session(WINDOW_SIZE, self->session_requests));
    }
  else
    {
      PROTOCOL_ERROR(e, "trailing garbage in open message");
    }
}

struct channel_open *
make_open_session(struct alist *session_requests)
{
  NEW(open_session, closure);

  closure->super.handler = do_open_session;
  closure->session_requests = session_requests;
  
  return &closure->super;
}


struct lsh_string *
format_exit_signal(struct ssh_channel *channel,
		   int core, int signal)
{
  struct lsh_string *msg = ssh_format("Process killed by %lz.\n",
				      STRSIGNAL(signal));
  
  return format_channel_request(ATOM_EXIT_SIGNAL,
				channel,
				0,
				"%a%c%fS%z",
				signal_local_to_network(signal),
				core,
				msg, "");
}

struct lsh_string *
format_exit(struct ssh_channel *channel, int value)
{
  return format_channel_request(ATOM_EXIT_STATUS,
				channel,
				0,
				"%i", value);
}

/* GABA:
   (class
     (name exit_shell)
     (super exit_callback)
     (vars
       (session object server_session)))
*/

static void
do_exit_shell(struct exit_callback *c, int signaled,
	      int core, int value)
{
  CAST(exit_shell, closure, c);
  struct server_session *session = closure->session;
  struct ssh_channel *channel = &session->super;
  
  trace("server_session.c: do_exit_shell\n");
  
  /* NOTE: We don't close the child's stdio here. */

  if (!(channel->flags & CHANNEL_SENT_CLOSE))
    {
      verbose("server_session.c: Sending %a message on channel %i\n",
	      signaled ? ATOM_EXIT_SIGNAL : ATOM_EXIT_STATUS,
	      channel->channel_number);
      
      C_WRITE(channel->connection,
	      (signaled
	       ? format_exit_signal(channel, core, value)
	       : format_exit(channel, value)) );

      /* We want to close the channel as soon as all stdout and stderr
       * data has been sent. In particular, we don't wait for EOF from
       * the client, most clients never sends that. */
      
      channel->flags |= (CHANNEL_NO_WAIT_FOR_EOF | CHANNEL_CLOSE_AT_EOF);
      
      if (channel->flags & CHANNEL_SENT_EOF)
	{
	  /* We have sent EOF already, so initiate close */
	  channel_close(channel);
	}
    }
}

static struct exit_callback *
make_exit_shell(struct server_session *session)
{
  NEW(exit_shell, self);

  self->super.exit = do_exit_shell;
  self->session = session;

  return &self->super;
}


static int
make_pipes(int *in, int *out, int *err)
{
  int saved_errno;
  
  if (lsh_make_pipe(in))
    {
      if (lsh_make_pipe(out))
	{
	  if (lsh_make_pipe(err))
	    {
              return 1;
            }
	  saved_errno = errno;
          close(out[0]);
          close(out[1]);
        }
      else
	saved_errno = errno;
      close(in[0]);
      close(in[1]);
    }
  else
    saved_errno = errno;
  
  errno = saved_errno;
  return 0;
}

#define BASH_WORKAROUND 1

#if WITH_PTY_SUPPORT

/* Sets certain fd:s to -1, which means that the slave tty should be
 * used (for the child), or that the stdout fd should be duplicated
 * (for the parent). */
static int
make_pty(struct pty_info *pty, int *in, int *out, int *err)
{
  debug("make_pty... ");

  assert(pty);
  
  debug("exists: \n"
        "  alive = %i\n"
        "  master = %i\n"
        "... ",
        pty->super.alive, pty->master);
  debug("\n");
  
  if (pty) 
    {
      assert(pty->super.alive);
      
      debug("make_pty: Using allocated pty.\n");

      /* Ownership of the master fd is passed on to some file
       * object. We need an fd for window_change_request, but we have
       * to use our regular fd:s to the master side, or we're
       * disrupt EOF handling on either side. */

      pty->super.alive = 0;
      
      /* FIXME: It seems unnecessary to dup all the fd:s here. We
       * could use a single lsh_fd object for the master side of the
       * pty. */

      /* -1 means opening deferred to the child */
      in[0] = -1;
      in[1] = pty->master;
      
      if ((out[0] = dup(pty->master)) < 0)
        {
          werror("make_pty: duping master pty to stdout failed (errno = %i): %z\n",
                 errno, STRERROR(errno));

          return 0;
        }

      out[1] = -1;

      /* pty_info no longer owns the pty fd */
      pty->master = -1;

#if BASH_WORKAROUND
      /* Don't use a separate stderr channel; just dup the
       * stdout pty to stderr. */
            
      err[0] = -1;
      err[1] = -1;
      
#else /* !BASH_WORKAROUND */
      if (!lsh_make_pipe(err))
        {
          close(in[1]);
          close(out[0]);
	  
          return 0;
        }
#endif /* !BASH_WORKAROUND */
      return 1;
    }
  return 0;
}

#else /* !WITH_PTY_SUPPORT */
static int make_pty(struct pty_info *pty UNUSED,
		    int *in UNUSED, int *out UNUSED, int *err UNUSED)
{ return 0; }
#endif /* !WITH_PTY_SUPPORT */

/* Returns -1 on failure, 0 for child and +1 for parent */
static int
spawn_process(struct server_session *session,
	      struct lsh_user *user,
	      struct address_info *peer)
{
  struct lsh_process *child;
    
  int in[2];
  int out[2];
  int err[2];

  /* Pipe used for syncronization. */
  int sync[2];
  
  if (session->process)
    /* Already spawned a shell or command */
    return -1;
  
  /* {in|out|err}[0] is for reading,
   * {in|out|err}[1] for writing. */

  if (!lsh_make_pipe(sync))
    {
      werror("spawn_process: Failed to create syncronization pipe.\n");
      return -1;
    }
  if (session->pty && !make_pty(session->pty, in, out, err))
    {
      KILL_RESOURCE(&session->pty->super);
      KILL(session->pty);
      session->pty = NULL;
    }

  if (!session->pty && !make_pipes(in, out, err))
    return -1;

  if (USER_FORK(user, &child,
		make_exit_shell(session),
		peer, session->pty ? session->pty->tty_name : NULL))
    {
      if (child)
	{ /* Parent */
	  char dummy;
	  int res;
	  struct ssh_channel *channel = &session->super;
	  
	  trace("spawn_process: Parent process\n");
	    
	  session->process = child;

	  /* Close the child's fd:s */
	  close(in[0]);
	  close(out[1]);
	  close(err[1]);

	  close(sync[1]);

	  /* On Solaris, reading the master side of the pty before the
	   * child has opened the slave side of it results in EINVAL.
	   * We can't have that, so we'll wait until the child has
	   * opened the tty, after which it should close its end of
	   * the syncronizatino pipe, and our read will return 0.
	   *
	   * We need the syncronizatino only if we're actually using a
	   * pty, but for simplicity, we do it every time. */

	  do
	    res = read(sync[0], &dummy, 1);
	  while (res < 0 && errno == EINTR);

	  close(sync[0]);
	  
	  {
	    /* Exception handlers */
	    struct exception_handler *io_exception_handler
	      = make_channel_io_exception_handler(channel,
						  "lshd: Child stdio: ",
						  &default_exception_handler,
						  HANDLER_CONTEXT);

	    /* Close callback for stderr and stdout */
	    struct lsh_callback *read_close_callback
	      = make_channel_read_close_callback(channel);

	    session->in
	      = io_write(make_lsh_fd(in[1], "child stdin",
				     io_exception_handler),
			 SSH_MAX_PACKET, NULL);
	  
	    /* Flow control */
	    session->in->write_buffer->report = &session->super.super;

	    /* FIXME: Should we really use the same exception handler,
	     * which will close the channel on read errors, or is it
	     * better to just send EOF on read errors? */
	    session->out
	      = io_read(make_lsh_fd(out[0], "child stdout",
				    io_exception_handler),
			make_channel_read_data(channel),
			read_close_callback);
	    session->err 
	      = ( (err[0] != -1)
		  ? io_read(make_lsh_fd(err[0], "child stderr",
					io_exception_handler),
			    make_channel_read_stderr(channel),
			    read_close_callback)
		  : NULL);
	  }
	
	  channel->receive = do_receive;
	  channel->send_adjust = do_send_adjust;
	  channel->eof = do_eof;
	  
	  /* Make sure that the process and it's stdio is
	   * cleaned up if the channel or connection dies. */
	  remember_resource
	    (channel->resources, &child->super);

	  /* FIXME: How to do this properly if in and out may use the
	   * same fd? */
	  remember_resource
	    (channel->resources, &session->in->super);
	  remember_resource
	    (channel->resources, &session->out->super);
	  if (session->err)
	    remember_resource
	      (channel->resources, &session->err->super);

	  /* Don't close channel immediately at EOF, as we want to
	   * get a chance to send exit-status or exit-signal. */
	  session->super.flags &= ~CHANNEL_CLOSE_AT_EOF;
	  return 1;
	}
      else
	{ /* Child */
	  int tty = -1;
	  trace("spawn_process: Child process\n");
	  assert(getuid() == user->uid);

#if 0
	  /* Debug timing problems */
	  if (sleep(5))
	    {
	      trace("server_session.c: sleep interrupted\n");

	      sleep(5);
	    }
#endif    
	  if (!USER_CHDIR_HOME(user))
	    {
	      werror("Could not change to home (or root) directory!\n");
	      _exit(EXIT_FAILURE);
	    }
	    
#if WITH_PTY_SUPPORT
	  if (session->pty)
	    {
	      debug("lshd: server.c: Opening slave tty...\n");
	      if ( (tty = pty_open_slave(session->pty)) < 0)
		{
		  debug("lshd: server.c: "
			"Opening slave tty... Failed!\n");
		  werror("lshd: Can't open controlling tty for child!\n");
		  _exit(EXIT_FAILURE);
		}
	      else
		debug("lshd: server.c: Opening slave tty... Ok.\n");
	    }
#endif /* WITH_PTY_SUPPORT */

	  /* Now any tty processing is done, so notify our parent by
	   * closing the syncronization pipe. */

	  close(sync[0]); close(sync[1]);
	  
	  /* Close all descriptors but those used for communicationg
	   * with parent. We rely on the close-on-exec flag for all
	   * other fd:s. */

	  if (dup2(in[0] >= 0 ? in[0] : tty, STDIN_FILENO) < 0)
	    {
	      werror("Can't dup stdin!\n");
	      _exit(EXIT_FAILURE);
	    }

	  if (dup2(out[1] >= 0 ? out[1] : tty, STDOUT_FILENO) < 0)
	    {
	      werror("Can't dup stdout!\n");
	      _exit(EXIT_FAILURE);
	    }

	  if (!dup_error_stream())
	    {
	      werror("server_session: Failed to dup old stderr. Bye.\n");
	      set_error_ignore();
	    }

	  if (dup2(err[1] >= 0 ? err[1] : tty, STDERR_FILENO) < 0)
	    {
	      werror("Can't dup stderr!\n");
	      _exit(EXIT_FAILURE);
	    }

	  /* Unconditionally close all the fd:s, no matter if some
	   * of them are -1. */
	  close(in[0]);
	  close(in[1]);
	  close(out[0]);
	  close(out[1]);
	  close(err[0]);
	  close(err[1]);
	  close(tty);
	    
	  return 0;
	}
    }
  /* fork failed */
  /* Close all fd:s */

  close(err[0]);
  close(err[1]);
  close(out[0]);
  close(out[1]);
  close(in[0]);
  close(in[1]);

  return -1;
}

DEFINE_CHANNEL_REQUEST(shell_request_handler)
     (struct channel_request *s UNUSED,
      struct ssh_channel *channel,
      struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);

  static struct exception shell_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Shell request failed");

  if (!parse_eod(args))
    {
      PROTOCOL_ERROR(e, "Invalid shell CHANNEL_REQUEST message.");
      return;
    }
    
  if (session->process)
    /* Already spawned a shell or command */
    goto fail;

  switch (spawn_process(session, channel->connection->user,
			channel->connection->peer))
    {
    case 1: /* Parent */
      /* NOTE: The return value is not used. */
      COMMAND_RETURN(c, channel);
      channel_start_receive(channel, session->initial_window);
      return;
    case 0:
      { /* Child */
#define MAX_ENV 1
	/* No args, and the USER_EXEC method fills in argv[0]. */
	const char *argv[] = { NULL, NULL };
	
	struct env_value env[MAX_ENV];
	int env_length = 0;
	
	debug("do_spawn_shell: Child process\n");
	assert(getuid() == channel->connection->user->uid);
	    	    
	if (session->term)
	  {
	    env[env_length].name ="TERM";
	    env[env_length].value = session->term;
	    env_length++;
	  }
	assert(env_length <= MAX_ENV);
#undef MAX_ENV

#if 1
	USER_EXEC(channel->connection->user, 1, argv, env_length, env);
	
	/* exec failed! */
	verbose("server_session: exec failed (errno = %i): %z\n",
		errno, STRERROR(errno));
	_exit(EXIT_FAILURE);

#else
# define GREETING "Hello world!\n"
	if (write(STDOUT_FILENO, GREETING, strlen(GREETING)) < 0)
	  _exit(errno);
	kill(getuid(), SIGSTOP);
	if (write(STDOUT_FILENO, shell, strlen(shell)) < 0)
	  _exit(125);
	_exit(126);
# undef GREETING
#endif
      }
    case -1:
      /* fork failed */

      break;
    default:
      fatal("Internal error!");
  }
 fail:
  EXCEPTION_RAISE(e, &shell_request_failed);
}

DEFINE_CHANNEL_REQUEST(exec_request_handler)
     (struct channel_request *s UNUSED,
      struct ssh_channel *channel,
      struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);

  static struct exception exec_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Exec request failed");
  
  UINT32 command_len;
  const UINT8 *command;

  if (!(parse_string(args, &command_len, &command)
	&& parse_eod(args)))
    {
      PROTOCOL_ERROR(e, "Invalid exec CHANNEL_REQUEST message.");
      return;
    }
    
  if (/* Already spawned a shell or command */
      session->process
      /* Command can't contain NUL characters. */
      || memchr(command, '\0', command_len))
    
    EXCEPTION_RAISE(e, &exec_request_failed);
  else
    {
      struct lsh_string *command_line = ssh_format("%ls", command_len, command);
      
      switch (spawn_process(session, channel->connection->user,
			    channel->connection->peer))
	{
	case 1: /* Parent */
	  lsh_string_free(command_line);
	  
	  /* NOTE: The return value is not used. */
	  COMMAND_RETURN(c, channel);
	  channel_start_receive(channel, session->initial_window);
	  return;
	case 0:
	  { /* Child */
#define MAX_ENV 1
	    struct env_value env[MAX_ENV];
	    int env_length = 0;
	    
	    /* No args, and the USER_EXEC method fills in argv[0]. */

	    /* NOTE: I'd like to use an array initializer, but that's
	     * not ANSI-C, and at least HPUX' compiler can't handle
	     * it. */
	    
	    const char *argv[4];
	    argv[0] = NULL;
	    argv[1] = "-c";
	    argv[2] = lsh_get_cstring(command_line);
	    argv[3] = NULL;
	
	    debug("do_spawn_shell: Child process\n");

	    assert(getuid() == channel->connection->user->uid);
	    assert(argv[2]);

	    /* FIXME: Set SSH_TTY, SSH_CLIENT and SSH_ORIGINAL_COMMAND */
	    if (session->term)
	      {
		env[env_length].name ="TERM";
		env[env_length].value = session->term;
		env_length++;
	      }
	    assert(env_length <= MAX_ENV);
#undef MAX_ENV

	    USER_EXEC(channel->connection->user, 0, argv, env_length, env);
	
	    /* exec failed! */
	    verbose("server_session: exec failed (errno = %i): %z\n",
		    errno, STRERROR(errno));
	    _exit(EXIT_FAILURE);
	  }
	case -1:
	  /* fork failed */
	  lsh_string_free(command_line);
	  EXCEPTION_RAISE(e, &exec_request_failed);

	  break;
	default:
	  fatal("Internal error!");
	}
    }
}

/* For simplicity, represent a subsystem simply as a name of the
 * executable. */

/* GABA:
   (class
     (name subsystem_request)
     (super channel_request)
     (vars
       ;(subsystems object alist)
       ; A list { name, program, name, program, NULL }
       (subsystems . "const char **")))
*/

/* ;; GABA:
   (class
     (name sybsystem_info)
     (vars
       (name "const char *")))
*/

static const char *
lookup_subsystem(struct subsystem_request *self,
		 UINT32 length, const UINT8 *name)
{
  unsigned i;
  if (memchr(name, 0, length))
    return NULL;

  for (i = 0; self->subsystems[i]; i+=2)
    {
      assert(self->subsystems[i+1]);
      if ((length == strlen(self->subsystems[i]))
	  && !memcmp(name, self->subsystems[i], length))
	return self->subsystems[i + 1];
    }
  return NULL;
}

static void
do_spawn_subsystem(struct channel_request *s,
		   struct ssh_channel *channel,
		   struct channel_request_info *info UNUSED,
		   struct simple_buffer *args,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(subsystem_request, self, s);
  CAST(server_session, session, channel);

  static struct exception subsystem_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Subsystem request failed");

  const UINT8 *name;
  UINT32 name_length;

  const char *program;
      
  if (! (parse_string(args, &name_length, &name) && parse_eod(args)))
    {
      PROTOCOL_ERROR(e, "Invalid subsystem CHANNEL_REQUEST message.");
      return;
    }
  
  program = lookup_subsystem(self, name_length, name);
  
  if (!session->process && program)
    {
      /* Don't use any pty */
      if (session->pty)
	{
	  KILL_RESOURCE(&session->pty->super);
	  session->pty = NULL;
	}
      
      switch (spawn_process(session, channel->connection->user,
			    channel->connection->peer))
	{
	case 1: /* Parent */
	  /* NOTE: The return value is not used. */
	  COMMAND_RETURN(c, channel);
	  channel_start_receive(channel, session->initial_window);
	  return;

	case 0: /* Child */
	  {
	    /* No args, and the USER_EXEC method fills in argv[0]. */
	    const char *argv[] = { NULL, NULL };

	    debug("do_spawn_subsystem: Child process\n");
	  
	    USER_EXEC(channel->connection->user, 1, argv, 0, NULL);

	    werror("server_session: subsystem exec failed (errno = %i): %z\n",
		   errno, STRERROR(errno));
	    _exit(EXIT_FAILURE);
	  }
	case -1: /* Error */
	  break;

	default:
	  fatal("Internal error!");
	}
    }
  EXCEPTION_RAISE(e, &subsystem_request_failed);
}

struct channel_request *
make_subsystem_handler(const char **subsystems)
{
  NEW(subsystem_request, self);

  self->super.handler = do_spawn_subsystem;
  self->subsystems = subsystems;
  
  return &self->super;
}


#if WITH_PTY_SUPPORT

/* pty_handler */
static void
do_alloc_pty(struct channel_request *c UNUSED,
	     struct ssh_channel *channel,
	     struct channel_request_info *info UNUSED,
	     struct simple_buffer *args,
	     struct command_continuation *s,
	     struct exception_handler *e)
{
  struct lsh_string *term = NULL;

  static struct exception pty_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "pty request failed");

  struct pty_info *pty = make_pty_info();
  
  CAST(server_session, session, channel);

  verbose("Client requesting a tty...\n");

  if ((term = parse_string_copy(args))
      && parse_uint32(args, &pty->dims.char_width)
      && parse_uint32(args, &pty->dims.char_height)
      && parse_uint32(args, &pty->dims.pixel_width)
      && parse_uint32(args, &pty->dims.pixel_height)
      && (pty->mode = parse_string_copy(args))
      && parse_eod(args))
    {
      /* The client may only request one tty, and only before
       * starting a process. */
      if (session->pty || session->process
	  || !pty_open_master(pty, channel->connection->user->uid))
	{
	  verbose("Pty allocation failed.\n");
	  EXCEPTION_RAISE(e, &pty_request_failed);
	}
      else
	{
	  /* FIXME: Perhaps we can set the window dimensions directly
	   * on the master pty? */
	  session->term = term;
	  session->pty = pty;
	  remember_resource(channel->resources, &pty->super);

	  verbose(" granted.\n");
	  COMMAND_RETURN(s, NULL);

	  /* Success */
	  return;
	}

    }
  else
    {
      werror("Invalid pty request.\n");
      PROTOCOL_ERROR(e, "Invalid pty request.");
    }
  /* Cleanup for failure cases. */
  lsh_string_free(term);
  KILL_RESOURCE(&pty->super);
  KILL(pty);
}

struct channel_request
pty_request_handler =
{ STATIC_HEADER, do_alloc_pty };

static void
do_window_change_request(struct channel_request *c UNUSED,
			 struct ssh_channel *channel,
			 struct channel_request_info *info UNUSED,
			 struct simple_buffer *args,
			 struct command_continuation *s,
			 struct exception_handler *e)
{
  struct terminal_dimensions dims;
  CAST(server_session, session, channel);

  verbose("Receiving window-change request...\n");

  if (parse_uint32(args, &dims.char_width)
      && parse_uint32(args, &dims.char_height)
      && parse_uint32(args, &dims.pixel_width)
      && parse_uint32(args, &dims.pixel_height)
      && parse_eod(args))
    {
      static const struct exception winch_request_failed =
	STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "window-change request failed: No pty");

      if (session->pty && session->in && session->in->super.alive
          && tty_setwinsize(session->in->fd, &dims))
        /* Success. Rely on the terminal driver sending SIGWINCH */
        COMMAND_RETURN(s, NULL);
      else
        EXCEPTION_RAISE(e, &winch_request_failed);
    }
  else
    PROTOCOL_ERROR(channel->connection->e, "Invalid window-change request.");
}

struct channel_request
window_change_request_handler =
{ STATIC_HEADER, do_window_change_request };

#endif /* WITH_PTY_SUPPORT */
