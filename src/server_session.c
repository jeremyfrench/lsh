/* server_session.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2002 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>

#include <signal.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "server_session.h"

#include "channel_io.h"
#include "environ.h"
#include "format.h"
#include "lsh_process.h"
#include "lsh_string.h"
#include "reaper.h"
#include "server.h"
#include "server_pty.h"
#include "server_x11.h"
#include "ssh.h"
#include "tcpforward.h"
#include "translate_signal.h"
#include "werror.h"
#include "xalloc.h"

#include "server_session.c.x"


/* Session */
/* GABA:
   (class
     (name server_session)
     (super ssh_channel)
     (vars
       (initial_window . uint32_t)

       ; Communication with the helper process
       (helper_fd . int)
       
       ; Resource to kill when the channel is closed. 
       (process object lsh_process)

       ; An allocated but not yet used pty
       (pty object pty_info)

       ; X11 forwarding.
       (x11 object server_x11_info)
       
       ; Value of the TERM environment variable
       (term string)

       ; Value for the SSH_CLIENT environment variable.
       ; FIXME: Currently not implemented.
       (client string)
       
       ; Child process stdio
       (in struct channel_write_state)
       (out struct channel_read_state)
       (err struct channel_read_state)))
*/

static void
do_kill_server_session(struct resource *s)
{  
  CAST(server_session, self, s);
  if (self->super.super.alive)
    {
      trace("do_kill_server_session\n");

      self->super.super.alive = 0;

      if (self->process)
	KILL_RESOURCE(&self->process->super);

      if (self->pty)
	KILL_RESOURCE(&self->pty->super);
      
      /* Doesn't use channel_write_state_close, since the channel is
	 supposedly dead already. */
      io_close_fd(self->in.fd);
      self->in.fd = -1;

      channel_read_state_close(&self->out);
      channel_read_state_close(&self->err);

      io_close_fd(self->out.fd);
      self->out.fd = -1;

      io_close_fd(self->err.fd);
      self->err.fd = -1;
    }
}

/* Receive channel data */

static void *
oop_write_stdin(oop_source *source UNUSED,
		int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(server_session, session, (struct lsh_object *) state);

  assert(event == OOP_WRITE);
  assert(fd == session->in.fd);

  if (channel_io_flush(&session->super, &session->in) != CHANNEL_IO_OK)
    channel_write_state_close(&session->super, &session->in);

  return OOP_CONTINUE;
}

static void
do_receive(struct ssh_channel *s, int type,
	   uint32_t length, const uint8_t *data)
{
  CAST(server_session, session, s);

  switch(type)
    {
    case CHANNEL_DATA:
      if (channel_io_write(&session->super, &session->in,
			   oop_write_stdin,
			   length, data) != CHANNEL_IO_OK)
	channel_write_state_close(&session->super, &session->in);

      break;
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      break;
    default:
      fatal("Internal error!\n");
    }
}

static void *
oop_read_stdout(oop_source *source UNUSED,
		int fd, oop_event event, void *state)
{
  CAST(server_session, session, (struct lsh_object *) state);
  uint32_t done;
  
  assert(fd == session->out.fd);
  assert(event == OOP_READ);

  if (channel_io_read(&session->super, &session->out, &done) != CHANNEL_IO_OK)
    channel_read_state_close(&session->out);

  else if (done > 0)
    channel_transmit_data(&session->super,
			  done, lsh_string_data(session->out.buffer));

  return OOP_CONTINUE;
}

static void *
oop_read_stderr(oop_source *source UNUSED,
		int fd, oop_event event, void *state)
{
  CAST(server_session, session, (struct lsh_object *) state);
  uint32_t done;
  
  assert(fd == session->err.fd);
  assert(event == OOP_READ);

  if (channel_io_read(&session->super, &session->err, &done) != CHANNEL_IO_OK)
    channel_read_state_close(&session->err);

  else if (done > 0)
    channel_transmit_extended(&session->super, SSH_EXTENDED_DATA_STDERR,
			      done, lsh_string_data(session->err.buffer));

  return OOP_CONTINUE;
}

/* We may send more data */
static void
do_send_adjust(struct ssh_channel *s,
	       uint32_t i UNUSED)
{
  CAST(server_session, session, s);

  channel_io_start_read(&session->super, &session->out, oop_read_stdout);
  channel_io_start_read(&session->super, &session->err, oop_read_stderr);
}

static void
do_server_session_event(struct ssh_channel *channel, enum channel_event event)
{
  CAST(server_session, session, channel);

  trace("server_session.c: do_server_session_event %i\n", event);

  switch(event)
    {
    case CHANNEL_EVENT_CLOSE:
    case CHANNEL_EVENT_CONFIRM:
    case CHANNEL_EVENT_DENY:
    case CHANNEL_EVENT_SUCCESS:
    case CHANNEL_EVENT_FAILURE:
      break;

    case CHANNEL_EVENT_EOF:
      if (session->pty)
	{
	  static const uint8_t eof[1] = { 4 }; /* ^D */
	  if (channel_io_write(channel, &session->in,
			       oop_write_stdin, sizeof(eof), eof) != CHANNEL_IO_OK)

	    channel_write_state_close(&session->super, &session->in);	
	}

      if (!session->in.state->length)
	channel_write_state_close(&session->super, &session->in);
      break;

    case CHANNEL_EVENT_STOP:
      channel_io_stop_read(&session->out);
      channel_io_stop_read(&session->err);
      break;

    case CHANNEL_EVENT_START:
      if (session->super.send_window_size)
	{
	  channel_io_start_read(&session->super,
				&session->out, oop_read_stdout);
	  channel_io_start_read(&session->super,
				&session->err, oop_read_stderr);
	}
      break;
    }
}

static struct ssh_channel *
make_server_session(uint32_t initial_window,
		    struct alist *request_types,
		    int helper_fd)
{
  NEW(server_session, self);

  init_channel(&self->super,
	       do_kill_server_session, do_server_session_event);

  /* We don't want to receive any data before we have forked some
   * process to receive it. */
  self->super.rec_window_size = 0;

  /* FIXME: Make maximum packet size configurable. */
  self->super.rec_max_packet = SSH_MAX_PACKET;
  self->super.request_types = request_types;

  self->initial_window = initial_window;

  self->helper_fd = helper_fd;

  self->process = NULL;

  self->pty = NULL;
  self->x11 = NULL;
  self->term = NULL;
  self->client = NULL;

  init_channel_write_state(&self->in, -1, 0);
  init_channel_read_state(&self->out, -1, 0);
  init_channel_read_state(&self->err, -1, 0);
  
  return &self->super;
}


/* GABA:
   (class
     (name open_session)
     (super channel_open)
     (vars
       (helper_fd . int)
       (session_requests object alist)))
*/

#define WINDOW_SIZE 10000

static void
do_open_session(struct channel_open *s,
		const struct channel_open_info *info,
		struct simple_buffer *args)
{
  CAST(open_session, self, s);

  debug("server.c: do_open_session\n");

  if (parse_eod(args))
    {
      channel_open_confirm(info,
			   make_server_session(WINDOW_SIZE,
					       self->session_requests,
					       self->helper_fd));
    }
  else
    {
      SSH_CONNECTION_ERROR(info->connection, "trailing garbage in open message");
    }
}

struct channel_open *
make_open_session(struct alist *session_requests, int helper_fd)
{
  NEW(open_session, self);

  self->super.handler = do_open_session;
  self->helper_fd = helper_fd;
  self->session_requests = session_requests;
  
  return &self->super;
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
      verbose("Sending %a message on channel %i.\n",
	      signaled ? ATOM_EXIT_SIGNAL : ATOM_EXIT_STATUS,
	      channel->remote_channel_number);

      if (signaled)
	channel_send_request(&session->super, ATOM_EXIT_SIGNAL, 0,
			     "%a%c%z%z",
			     signal_local_to_network(value),
			     core,
			     STRSIGNAL(value), "");
      else
	channel_send_request(&session->super, ATOM_EXIT_STATUS, 0,
			     "%i", value);

      /* We want to close the channel as soon as all stdout and stderr
       * data has been sent. In particular, we don't wait for EOF from
       * the client, most clients never sends that. */
      
      channel->flags |= CHANNEL_NO_WAIT_FOR_EOF;

      /* This message counts as one "sink" (bad name, right) */
      assert(channel->sinks);
      channel->sinks--;
      channel_maybe_close(channel);
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
      
      /* FIXME: It seems unnecessary to dup the master fd here. But
	 for simplicity of ownership, keep one copy in the pty_info
	 object, one for stdin, and one for stdout. */

      /* -1 means opening deferred to the child */
      in[0] = -1;
      if ((in[1] = dup(pty->master)) < 0)
        {
          werror("make_pty: duping master pty for stdin failed %e.\n", errno);

          return 0;
        }      
      if ((out[0] = dup(pty->master)) < 0)
        {
          werror("make_pty: duping master pty for stdout failed %e.\n", errno);

          return 0;
        }

      out[1] = -1;

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

#define SERVER_READ_BUFFER_SIZE 0x4000

static int
spawn_process(struct server_session *session,
	      /* All information but the fd:s should be filled in
	       * already */
	      struct spawn_info *info)
{
  assert(!session->process);
  
  if (session->pty && !make_pty(session->pty,
				info->in, info->out, info->err))
    {
      KILL_RESOURCE(&session->pty->super);
      KILL(session->pty);
      session->pty = NULL;
    }

  if (!session->pty && !make_pipes(info->in, info->out, info->err))
    return 0;

  /* NOTE: Uses the info->pty->master. After this, it's ok to close
     that fd, but we currently don't do that until session death. */
  session->process = spawn_shell(info, session->helper_fd,
				 make_exit_shell(session));

  if (!session->process)
    return 0;

  /* One extra character, to make sure we can send a final ^D. */
  init_channel_write_state(&session->in, info->in[1], session->initial_window + 1);
  init_channel_read_state(&session->out, info->out[0], SERVER_READ_BUFFER_SIZE);
  io_register_fd(info->in[1], "process stdin");
  io_register_fd(info->out[0], "process stdout");

  if (session->pty)
    /* When the child process has exited, and hence the slave side of
       the pty is closed, then read, at least on linux, returns EIO.
       This should be treated as an EOF event, not an error. */
    session->out.ignored_error = EIO;

  session->super.sources++;

  if (info->err[0] < 0)
    {
      session->err.fd = -1;
      session->err.buffer = NULL;
    }
  else
    {
      init_channel_read_state(&session->err, info->err[0], SERVER_READ_BUFFER_SIZE);
      io_register_fd(info->err[0], "process stderr");

      session->super.sources++;
    }

  if (session->super.send_window_size)
    {
      channel_io_start_read(&session->super, &session->out, oop_read_stdout);
      channel_io_start_read(&session->super, &session->err, oop_read_stderr);
    }
  
  session->super.receive = do_receive;
  session->super.send_adjust = do_send_adjust;
  
  /* One reference for stdin, and one for the exit-status/exit-signal
     message */
  session->super.sinks += 2;

  channel_start_receive(&session->super, session->initial_window);

  return 1;
}

static void
init_spawn_info(struct spawn_info *info, struct server_session *session,
		const char **argv,
		unsigned env_length, struct env_value *env)
{
  unsigned i = 0;
  
  memset(info, 0, sizeof(*info));

  info->pty = session->pty;
  info->argv = argv;
  
  assert(env_length >= 5);

  /* FIXME: Set SSH_ORIGINAL_COMMAND */
  if (session->term)
    {
      env[i].name = ENV_TERM;
      env[i].value = lsh_get_cstring(session->term);
      i++;
    }

  if (info->pty && info->pty->tty_name)
    {
      env[i].name = ENV_SSH_TTY;
      env[i].value = lsh_get_cstring(info->pty->tty_name);
      i++;
    }

#if WITH_X11_FORWARD
  if (session->x11)
    {
      env[i].name = ENV_DISPLAY;
      env[i].value = lsh_get_cstring(session->x11->display);
      i++;

      env[i].name = ENV_XAUTHORITY;
      env[i].value = lsh_get_cstring(session->x11->xauthority);
      i++;
    }
#endif /* WITH_X11_FORWARD */
  assert(i <= env_length);
  info->env_length = i;
  info->env = env;
}

DEFINE_CHANNEL_REQUEST(shell_request_handler)
     (struct channel_request *s UNUSED,
      struct ssh_channel *channel,
      const struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);
  struct spawn_info spawn;
  struct env_value env[5];
  
  static const struct exception shell_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, 0, "Shell request failed");

  trace("shell_request_handler\n");
  if (!parse_eod(args))
    {
      SSH_CONNECTION_ERROR(channel->connection,
			   "Invalid shell CHANNEL_REQUEST message.");
      return;
    }
    
  if (session->process)
    /* Already spawned a shell or command */
    goto fail;

  init_spawn_info(&spawn, session, NULL, 5, env);
  spawn.login = 1;

  if (spawn_process(session, &spawn))
    COMMAND_RETURN(c, channel);
  else
    {
    fail:
      EXCEPTION_RAISE(e, &shell_request_failed);
    }
}

DEFINE_CHANNEL_REQUEST(exec_request_handler)
     (struct channel_request *s UNUSED,
      struct ssh_channel *channel,
      const struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);

  static const struct exception exec_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, 0, "Exec request failed");
  
  uint32_t command_len;
  const uint8_t *command;

  if (!(parse_string(args, &command_len, &command)
	&& parse_eod(args)))
    {
      SSH_CONNECTION_ERROR(channel->connection,
			   "Invalid exec CHANNEL_REQUEST message.");
      return;
    }
    
  if (/* Already spawned a shell or command */
      session->process
      /* Command can't contain NUL characters. */
      || memchr(command, '\0', command_len))
    
    EXCEPTION_RAISE(e, &exec_request_failed);
  else
    {
      struct spawn_info spawn;
      const char *args[4] = { NULL, "-c", NULL, NULL };
      struct env_value env[5];

      struct lsh_string *s = ssh_format("%ls", command_len, command);
      args[2] = lsh_get_cstring(s);
      
      init_spawn_info(&spawn, session, args, 5, env);
      spawn.login = 0;      
      
      if (spawn_process(session, &spawn))
	COMMAND_RETURN(c, channel);
      else
	EXCEPTION_RAISE(e, &exec_request_failed);

      lsh_string_free(s);
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

static void
do_spawn_subsystem(struct channel_request *s,
		   struct ssh_channel *channel,
		   const struct channel_request_info *info UNUSED,
		   struct simple_buffer *args,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(subsystem_request, self, s);
  CAST(server_session, session, channel);

  static const struct exception subsystem_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, 0, "Subsystem request failed");

  const uint8_t *name;
  uint32_t name_length;

  const char *program;
      
  if (! (parse_string(args, &name_length, &name) && parse_eod(args)))
    {
      SSH_CONNECTION_ERROR(channel->connection,
			   "Invalid subsystem CHANNEL_REQUEST message.");
      return;
    }
  
  program = server_lookup_module(self->subsystems, name_length, name);
  
  if (!session->process && program)
    {
      struct spawn_info spawn;
      const char *args[4] = { NULL, "-c", NULL, NULL };
      struct env_value env[5];

      /* Don't use any pty */
      if (session->pty)
	{
	  KILL_RESOURCE(&session->pty->super);
	  session->pty = NULL;
	}

      args[2] = program;
      
      init_spawn_info(&spawn, session, args, 5, env);
      spawn.login = 0;

      if (spawn_process(session, &spawn))
	{
	  COMMAND_RETURN(c, channel);
	  return;
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
DEFINE_CHANNEL_REQUEST(pty_request_handler)
     (struct channel_request *c UNUSED,
      struct ssh_channel *channel,
      const struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *s,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);
  struct lsh_string *term = NULL;
  uint32_t char_width;
  uint32_t char_height;
  uint32_t pixel_width;
  uint32_t pixel_height;

  static const struct exception pty_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, 0, "pty request failed");

  struct pty_info *pty = make_pty_info();

  verbose("Client requesting a tty...\n");

  if ((term = parse_string_copy(args))
      && parse_uint32(args, &char_width)
      && parse_uint32(args, &char_height)
      && parse_uint32(args, &pixel_width)
      && parse_uint32(args, &pixel_height)
      && (pty->mode = parse_string_copy(args))
      && parse_eod(args))
    {
      /* The client may only request one tty, and only before
       * starting a process. */

      pty->dims.ws_col = char_width;
      pty->dims.ws_row = char_height;
      pty->dims.ws_xpixel = pixel_height;
      pty->dims.ws_ypixel = pixel_width;

      if (session->pty || session->process
	  || !pty_open_master(pty))
	{
	  werror("pty_request_handler: pty %s NULL, process %s NULL\n",
		 session->pty ? "!=" : "=", session->process ? "!=" : "=");
	  verbose("Pty allocation failed.\n");
	  EXCEPTION_RAISE(e, &pty_request_failed);
	}
      else
	{
	  /* FIXME: Perhaps we can set the window dimensions directly
	   * on the master pty? */
	  session->term = term;
	  session->pty = pty;

	  verbose(" ... granted.\n");
	  debug("pty master fd: %i\n", pty->master);
	  COMMAND_RETURN(s, channel);

	  /* Success */
	  return;
	}
    }
  else
    {
      werror("Invalid pty request.\n");
      SSH_CONNECTION_ERROR(channel->connection, "Invalid pty request.");
    }
  /* Cleanup for failure cases. */
  lsh_string_free(term);
  KILL_RESOURCE(&pty->super);
  KILL(pty);
}

DEFINE_CHANNEL_REQUEST(window_change_request_handler)
	(struct channel_request *c UNUSED,
	 struct ssh_channel *channel,
	 const struct channel_request_info *info UNUSED,
	 struct simple_buffer *args,
	 struct command_continuation *s,
	 struct exception_handler *e)
{
  CAST(server_session, session, channel);
  uint32_t char_width;
  uint32_t char_height;
  uint32_t pixel_width;
  uint32_t pixel_height;
  struct winsize dims;

  verbose("Receiving window-change request...\n");

  if (parse_uint32(args, &char_width)
      && parse_uint32(args, &char_height)
      && parse_uint32(args, &pixel_width)
      && parse_uint32(args, &pixel_height)
      && parse_eod(args))
    {
      static const struct exception winch_request_failed =
	STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, 0,
			 "window-change request failed: No pty");

      dims.ws_col = char_width;
      dims.ws_row = char_height;
      dims.ws_xpixel = pixel_height;
      dims.ws_ypixel = pixel_width;

      if (session->pty && session->in.fd >= 0
          && ioctl(session->in.fd, TIOCSWINSZ, &dims) != -1)
        /* Success. Rely on the terminal driver sending SIGWINCH */
        COMMAND_RETURN(s, channel);
      else
        EXCEPTION_RAISE(e, &winch_request_failed);
    }
  else
    SSH_CONNECTION_ERROR(channel->connection,
			 "Invalid window-change request.");
}

#endif /* WITH_PTY_SUPPORT */

#if 0
#if WITH_X11_FORWARD

/* FIXME: We must delay the handling of any shell request until we
 * have responded to the x11-req message. Or maybe leave that problem
 * to the client? */
DEFINE_CHANNEL_REQUEST(x11_request_handler)
     (struct channel_request *s UNUSED,
      struct ssh_channel *channel,
      struct channel_request_info *info UNUSED,
      struct simple_buffer *args,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(server_session, session, channel);

  static const struct exception x11_request_failed =
    STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "x11-req failed");

  const uint8_t *protocol;
  uint32_t protocol_length;
  const uint8_t *cookie;
  uint32_t cookie_length;
  uint32_t screen;
  unsigned single;

  verbose("Client requesting x11 forwarding...\n");

  if (parse_uint8(args, &single)
      && parse_string(args, &protocol_length, &protocol)
      && parse_string(args, &cookie_length, &cookie)
      && parse_uint32(args, &screen))
    {
      /* The client may only request one x11-forwarding, and only
       * before starting a process. */
      if (session->x11 || session->process
	  || !(session->x11 = server_x11_setup(channel,
					       single,
					       protocol_length, protocol,
					       cookie_length, cookie,
					       screen, c, e)))
	{
	  verbose("X11 request failed.\n");
	  EXCEPTION_RAISE(e, &x11_request_failed);
	}
      else
	{	  
	  return;
	}
    }
  else
    {
      werror("Invalid x11 request.\n");
      SSH_CONNECTION_ERROR(channel->connection, "Invalid x11 request.");
    }
}

#endif /* WITH_X11_FORWARD */
#endif
