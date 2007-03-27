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

      KILL_RESOURCE_LIST(self->resources);
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
/* FIXME: Escape char handling */

static void *
oop_read_stdin(oop_source *source UNUSED,
	       int fd, oop_event event, void *state)
{
  CAST(client_session, session, (struct lsh_object *) state);
  uint32_t done;
  
  assert(fd == session->in.fd);
  assert(event == OOP_READ);

  if (channel_io_read(&session->super, &session->in, &done) != CHANNEL_IO_OK)
    {
      /* This resource list is used only for tty-related things.
	 Killing it will restore the tty modes. */
      KILL_RESOURCE_LIST (session->resources);
      channel_read_state_close(&session->in);
    }
  else if (done > 0)
    {
      /* FIXME: Look for escape char */
      channel_transmit_data(&session->super,
			    done, lsh_string_data(session->in.buffer));
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

      /* FIXME: Setup escape handler, and raw tty? */
      if (session->super.send_window_size)
	channel_io_start_read(&session->super, &session->in, oop_read_stdin);

      ALIST_SET(session->super.request_types, ATOM_EXIT_STATUS,
		&make_handle_exit_status(session->exit_status)->super);
      ALIST_SET(session->super.request_types, ATOM_EXIT_SIGNAL,
		&make_handle_exit_signal(session->exit_status)->super);

      while (!object_queue_is_empty(&session->requests))
	{
	  CAST_SUBTYPE(command, request,
		       object_queue_remove_head(&session->requests));
	  COMMAND_CALL(request, &session->super.super.super,
		       &discard_continuation, session->e);
	}

      channel_start_receive(&session->super,
			    lsh_string_length(session->out.state->buffer));

      break;

    case CHANNEL_EVENT_DENY:
      EXCEPTION_RAISE(session->e,
		      make_exception(EXC_CHANNEL_OPEN, 0,
				     "Failed to open session channel."));
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

    case CHANNEL_EVENT_STOP:
      channel_io_stop_read(&session->in);
      break;
    case CHANNEL_EVENT_START:
      if (session->super.send_window_size)
	channel_io_start_read(&session->super, &session->in, oop_read_stdin);
      break;
    }
}  

#define CLIENT_READ_BUFFER_SIZE 0x4000

struct client_session *
make_client_session_channel(int in, int out, int err,
			    struct exception_handler *e,
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

  self->super.request_types = make_alist(0, -1);

  init_channel_read_state(&self->in, in, CLIENT_READ_BUFFER_SIZE);
  init_channel_write_state(&self->out, out, initial_window);
  init_channel_write_state(&self->err, err, initial_window);

  io_register_fd(in, "session stdin");
  io_register_fd(out, "session stdout");
  io_register_fd(err, "session stderr");

  self->resources = make_resource_list();

  object_queue_init(&self->requests);
  self->e = e;

  self->escape = escape;

#if 0
  /* Implement send break */
  if (self->escape)
    self->escape->dispatch['b'] = make_send_break(self->super);
#endif

  self->exit_status = exit_status;
  
  return self;
}
