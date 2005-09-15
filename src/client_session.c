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

#include "channel_commands.h"
#include "channel_io.h"
#include "client.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "ssh_write.h"
#include "werror.h"
#include "xalloc.h"

#include "client_session.c.x"


/* Initiate and manage a session */
/* GABA:
   (class
     (name client_session)
     (super ssh_channel)
     (vars
       ; Session stdio. The fd:s should be distinct, for simplicity in the close logic.
       (in struct channel_read_state)
       (out struct channel_write_state)
       (err struct channel_write_state)

       ; Escape char handling
       (escape object escape_info)
       ; Where to save the exit code.
       (exit_status . "int *")))
*/

static void
do_kill_client_session(struct resource *s)
{  
  CAST(client_session, self, s);
  if (self->super.super.alive)
    {
      trace("do_kill_client_session\n");

      self->super.super.alive = 0;

      /* Doesn't use channel_write_state_close, since the channel is
	 supposedly dead already. */
      channel_read_state_close(&self->in);

      io_close_fd(self->out.fd);
      self->out.fd = -1;

      io_close_fd(self->err.fd);
      self->err.fd = -1;

      channel_pending_close(self->super.table);
    }
}

/* Callback used when the server sends us eof */
static void
do_client_session_eof(struct ssh_channel *c)
{
  CAST(client_session, session, c);

  if (!session->out.state->length)
    channel_write_state_close(&session->super, &session->out);

  if (!session->err.state->length)
    channel_write_state_close(&session->super, &session->err);
}  

static void *
oop_write_stdout(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST(client_session, session, (struct lsh_object *) state);

  assert(event == OOP_WRITE);
  assert(fd == session->out.fd);

  channel_io_flush(&session->super, &session->out);
  return OOP_CONTINUE;
}

static void *
oop_write_stderr(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(client_session, session, (struct lsh_object *) state);

  assert(event == OOP_WRITE);
  assert(fd == session->err.fd);

  channel_io_flush(&session->super, &session->err);
  return OOP_CONTINUE;
}


/* FIXME: Use length, pointer instead of a string */
/* Receive channel data */
static void
do_receive(struct ssh_channel *s,
	   int type, struct lsh_string *data)
{
  CAST(client_session, session, s);
  
  switch(type)
    {
    case CHANNEL_DATA:
      channel_io_write(&session->super, &session->out,
		       oop_write_stdout,
		       STRING_LD(data));
      break;
    case CHANNEL_STDERR_DATA:
      channel_io_write(&session->super, &session->err,
		       oop_write_stderr,
		       STRING_LD(data));
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

  done = channel_io_read(&session->super, &session->in);

  if (done > 0)
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

/* Called when a session channel which a remote shell */
DEFINE_COMMAND(client_start_io)
     (struct command *s UNUSED,
      struct lsh_object *x,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(client_session, session, x);

  session->super.receive = do_receive;
  session->super.send_adjust = do_send_adjust;
  session->super.eof = do_client_session_eof;

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

  channel_start_receive(&session->super, lsh_string_length(session->out.state->buffer));

  COMMAND_RETURN(c, session);
}

#define CLIENT_READ_BUFFER_SIZE 0x4000

struct ssh_channel *
make_client_session_channel(int in, int out, int err,
			    struct escape_info *escape,
			    uint32_t initial_window,
			    int *exit_status)
{
  NEW(client_session, self);

  trace("make_client_session\n");
  init_channel(&self->super, do_kill_client_session);

  /* Set to initial_window in client_start_io */
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
  
  self->escape = escape;

#if 0
  /* Implement send break */
  if (self->escape)
    self->escape->dispatch['b'] = make_send_break(self->super);
#endif

  self->exit_status = exit_status;
  
  return &self->super;
}
