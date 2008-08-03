/* client_session.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "client.h"

#include "channel.h"
#include "channel_io.h"
#include "client.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "ssh_write.h"
#include "werror.h"
#include "xalloc.h"

#include "client_session.c.x"

static void
do_kill_client_session(struct resource *s)
{  
  CAST(client_session, self, s);
  if (self->super.super.alive)
    {
      trace("do_kill_client_session\n");

      self->super.super.alive = 0;

      channel_read_state_close(&self->in);

      /* Doesn't use channel_write_state_close, since the channel is
	 supposedly dead already. */
      io_close_fd(self->out.fd);
      self->out.fd = -1;

      io_close_fd(self->err.fd);
      self->err.fd = -1;

      if (self->pty)
	KILL_RESOURCE(self->pty);
      if (self->x11)
	KILL_RESOURCE(self->x11);

      ssh_connection_pending_close(self->super.connection);
    }
}

static void *
oop_write_stdout(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST(client_session, session, (struct lsh_object *) state);

  assert(event == OOP_WRITE);
  assert(fd == session->out.fd);

  if (channel_io_flush(&session->super, &session->out) != CHANNEL_IO_OK)
    channel_write_state_close(&session->super, &session->out);
  
  return OOP_CONTINUE;
}

static void *
oop_write_stderr(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(client_session, session, (struct lsh_object *) state);

  assert(event == OOP_WRITE);
  assert(fd == session->err.fd);

  if (channel_io_flush(&session->super, &session->err) != CHANNEL_IO_OK)
    channel_write_state_close(&session->super, &session->err);
  
  return OOP_CONTINUE;
}


/* Receive channel data */
static void
do_receive(struct ssh_channel *s, int type,
	   uint32_t length, const uint8_t *data)
{
  CAST(client_session, session, s);
  
  switch(type)
    {
    case CHANNEL_DATA:
      if (channel_io_write(&session->super, &session->out,
			   oop_write_stdout,
			   length, data) != CHANNEL_IO_OK)
	channel_write_state_close(&session->super, &session->out);

      break;
    case CHANNEL_STDERR_DATA:
      if (channel_io_write(&session->super, &session->err,
			   oop_write_stderr,
			   length, data) != CHANNEL_IO_OK)
	channel_write_state_close(&session->super, &session->err);

      break;
    default:
      fatal("Internal error!\n");
    }
}

/* Reading stdin */
static void *
oop_read_stdin(oop_source *source UNUSED,
	       int fd, oop_event event, void *state)
{
  CAST(client_session, session, (struct lsh_object *) state);
  uint32_t length;
  
  assert(fd == session->in.fd);
  assert(event == OOP_READ);

  if (channel_io_read(&session->super, &session->in, &length) != CHANNEL_IO_OK)
    {
      /* Killing the pty resource restores the tty modes. */
      if (session->pty)
	KILL_RESOURCE(session->pty);

      channel_read_state_close(&session->in);
    }
  else if (length > 0)
    {
      const uint8_t *data = lsh_string_data(session->in.buffer);

      if (session->escape)
	while (length > 0)
	  {
	    uint32_t copy;
	    uint32_t done;

	    session->escape_state
	      = client_escape_process(session->escape, session->escape_state,
				      length, data, &copy, &done);

	    if (copy > 0)
	      channel_transmit_data(&session->super, copy, data);
	      
	    data += done;
	    length -= done;
	  }	

      else
	channel_transmit_data(&session->super, length, data);
    }
  else
    {
      /* FIXME: We ought to warn the user if we're out of window
	 space, and turn the terminal back into canonical mode. */
      ;
    }
  return OOP_CONTINUE;
}

/* We may send more data */
static void
do_send_adjust(struct ssh_channel *s,
	       uint32_t i UNUSED)
{
  CAST(client_session, session, s);

  channel_io_start_read(&session->super, &session->in, oop_read_stdin);
}

static void
session_next_action(struct client_session *session)
{
  trace("session_next_action: next = %i, done = %i, length = %i\n",
	session->action_next, session->action_done,
	LIST_LENGTH(session->actions));

  while (session->action_next < LIST_LENGTH(session->actions))
    {
      CAST_SUBTYPE(client_session_action, action,
		   LIST(session->actions)[session->action_next]);

      if (action->serial && session->action_next > session->action_done)
	return;

      session->action_next++;
      action->start(action, session);
    }
}

static void
do_client_session_event(struct ssh_channel *c, enum channel_event event)
{
  CAST(client_session, session, c);

  switch(event)
    {
    case CHANNEL_EVENT_CONFIRM:
      session->super.receive = do_receive;
      session->super.send_adjust = do_send_adjust;

      session->super.sources ++;

      /* One reference each for stdout and stderr, and one more for the
	 exit-status/exit-signal message */
      session->super.sinks += 3;

      /* FIXME: Move channel_io_start_read to do_action_shell_success? */
      /* FIXME: Setup escape handler, and raw tty? */
      if (session->super.send_window_size)
	channel_io_start_read(&session->super, &session->in, oop_read_stdin);

      session_next_action(session);

      break;

    case CHANNEL_EVENT_DENY:
      /* FIXME: Do we need any additional error handling? */
      werror("Failed to open session channel.\n");
      break;
    case CHANNEL_EVENT_EOF:
      if (!session->out.state->length)
	channel_write_state_close(&session->super, &session->out);

      if (!session->err.state->length)
	channel_write_state_close(&session->super, &session->err);

      /* FIXME: Arrange for close when all data is written. */
      break;

    case CHANNEL_EVENT_CLOSE:
      /* Do nothing */
      break;

    case CHANNEL_EVENT_SUCCESS:
      assert(session->action_done < LIST_LENGTH(session->actions));
      {
	CAST_SUBTYPE(client_session_action, action,
		     LIST(session->actions)[session->action_done++]);

	if (action->success)
	  action->success(action, session);
	session_next_action(session);
      }
      break;
    case CHANNEL_EVENT_FAILURE:
      assert(session->action_done < LIST_LENGTH(session->actions));
      {
	CAST_SUBTYPE(client_session_action, action,
		     LIST(session->actions)[session->action_done++]);

	if (action->failure && action->failure(action, session))
	  session_next_action(session);
	else
	  channel_close(&session->super);
      }
      break;

    case CHANNEL_EVENT_STOP:
      channel_io_stop_read(&session->in);
      break;
    case CHANNEL_EVENT_START:
      if (session->super.send_window_size)
	channel_io_start_read(&session->super, &session->in, oop_read_stdin);
      break;
    }
}  

DEFINE_CHANNEL_REQUEST(handle_exit_status)
	(struct channel_request *s UNUSED,
	 struct ssh_channel *channel,
	 const struct request_info *info,
	 struct simple_buffer *args)
{
  CAST(client_session, session, channel);
  uint32_t status;

  if (!info->want_reply
      && parse_uint32(args, &status)
      && parse_eod(args))
    {
      verbose("client.c: Receiving exit-status %i on channel %i\n",
	      status, channel->remote_channel_number);

      *session->exit_status = status;
      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      assert(channel->sinks);
      channel->sinks--;
      channel_maybe_close(channel);
    }
  else
    /* Invalid request */
    SSH_CONNECTION_ERROR(channel->connection, "Invalid exit-status message");
}

DEFINE_CHANNEL_REQUEST(handle_exit_signal)
	(struct channel_request *s UNUSED,
	 struct ssh_channel *channel,
	 const struct request_info *info,
	 struct simple_buffer *args)
{
  CAST(client_session, session, channel);

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

      *session->exit_status = 7;

      werror("Remote process was killed by signal: %ups %z\n",
	     length, msg,
	     core ? "(core dumped remotely)\n": "");
      
      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      assert(channel->sinks);
      channel->sinks--;
      channel_maybe_close(channel);
    }
  else
    /* Invalid request */
    SSH_CONNECTION_ERROR(channel->connection, "Invalid exit-signal message");
}


#define CLIENT_READ_BUFFER_SIZE 0x4000

struct client_session *
make_client_session_channel(int in, int out, int err,
			    struct object_list *actions,
			    struct escape_info *escape,
			    uint32_t initial_window,
			    int *exit_status)
{
  NEW(client_session, self);

  trace("make_client_session\n");
  init_channel(&self->super, do_kill_client_session, do_client_session_event);

  /* Set to initial_window when channel_start_receive is called, in
     do_client_session_event. */
  self->super.rec_window_size = 0;

  /* FIXME: Make maximum packet size configurable */
  self->super.rec_max_packet = SSH_MAX_PACKET;

  self->super.request_types
    = make_alist(2,
		 ATOM_EXIT_STATUS, &handle_exit_status,
		 ATOM_EXIT_SIGNAL, &handle_exit_signal,
		 -1);

  init_channel_read_state(&self->in, in, CLIENT_READ_BUFFER_SIZE);
  init_channel_write_state(&self->out, out, initial_window);
  init_channel_write_state(&self->err, err, initial_window);

  io_register_fd(in, "session stdin");
  io_register_fd(out, "session stdout");
  io_register_fd(err, "session stderr");

  self->pty = NULL;
  self->x11 = NULL;

  self->actions = actions;
  self->action_next = 0;
  self->action_done = 0;

  self->escape = escape;
  self->escape_state = ESCAPE_GOT_NONE;

#if 0
  /* Implement send break */
  if (self->escape)
    self->escape->dispatch['b'] = make_send_break(self->super);
#endif

  self->exit_status = exit_status;
  
  return self;
}

static void
do_action_shell_start(struct client_session_action *s UNUSED,
		      struct client_session *session)
{
  verbose("Sending shell request.\n");
  channel_send_request(&session->super, ATOM_LD(ATOM_SHELL), 1, "");
}

static void
do_action_shell_success(struct client_session_action *s UNUSED,
			struct client_session *session)
{
  verbose("Shell/exec/subsystem request succeeded.\n");

  channel_start_receive(&session->super,
			lsh_string_length(session->out.state->buffer));
}

struct client_session_action client_request_shell =
  { STATIC_HEADER, 1, do_action_shell_start, do_action_shell_success, NULL };

/* Used for both exec and subsystem request. */
/* GABA:
   (class
     (name client_action_command)
     (super client_session_action)
     (vars
       (type . int)
       (arg string)))
*/

static void
do_action_command_start(struct client_session_action *s,
			struct client_session *session)
{
  CAST(client_action_command, self, s);

  verbose("Sending %a request\n", self->type);
  channel_send_request(&session->super, ATOM_LD(self->type), 1, "%S", self->arg);  
}

static struct client_session_action *
make_action_command(int type, struct lsh_string *arg)
{
  NEW(client_action_command, self);

  self->super.serial = 1;
  self->super.start = do_action_command_start;
  self->super.success = do_action_shell_success;
  self->super.failure = NULL;
  self->type = type;
  self->arg = arg;

  return &self->super;
}

struct client_session_action *
make_exec_action(struct lsh_string *command)
{
  return make_action_command(ATOM_EXEC, command);
}

struct client_session_action *
make_subsystem_action(struct lsh_string *subsystem)
{
  return make_action_command(ATOM_SUBSYSTEM, subsystem);
}
