/* client.c
 *
 * $Id$ */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* FIXME: Why include stdio? */
/* #include <stdio.h> */

#include "client.h"

#include "abstract_io.h"
#include "channel.h"
#include "channel_commands.h"
#include "connection.h"
#include "crypto.h"
#include "debug.h"
#include "encrypt.h"
#include "format.h"
#include "pad.h"
#include "parse.h"
#include "service.h"
#include "ssh.h"
#include "translate_signal.h"
#include "tty.h"
#include "unpad.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"
#include "compress.h"

#include <signal.h>

#include <string.h>
#include <assert.h>

#include "client.c.x"

/* Start a service that the server has accepted (for instance
 * ssh-userauth). */
/* GABA:
   (class
     (name accept_service_handler)
     (super packet_handler)
     (vars
       (service simple int)
       (c object command_continuation)
       ;; Do we really need the exception handler here?
       (e object exception_handler)))
*/

static void
do_accept_service(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(accept_service_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  int name;

  simple_buffer_init(&buffer, packet->length, packet->data);
  
  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_ACCEPT)
      && parse_atom(&buffer, &name)
      && parse_eod(&buffer)
      && (name == closure->service))
    {
      lsh_string_free(packet);
      connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = connection->fail;
      
      COMMAND_RETURN(closure->c, connection);
    }
  else
    {
      lsh_string_free(packet);
      EXCEPTION_RAISE(closure->e,
		      make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
					      "Invalid SSH_MSG_SERVICE_ACCEPT message"));
    }
}

struct packet_handler *
make_accept_service_handler(int service,
			    struct command_continuation *c,
			    struct exception_handler *e)
{
  NEW(accept_service_handler, closure);

  closure->super.handler = do_accept_service;
  closure->service = service;
  closure->c = c;
  closure->e = e;
  
  return &closure->super;
}

/* GABA:
   (class
     (name request_service)
     (super command)
     (vars
       (service simple int)))
       ;; (service object ssh_service)))
*/

static void
do_request_service(struct command *s,
		   struct lsh_object *x,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(request_service, self, s);
  CAST(ssh_connection, connection, x);
  
  connection->dispatch[SSH_MSG_SERVICE_ACCEPT]
    = make_accept_service_handler(self->service, c, e);
  
  C_WRITE(connection,
	  format_service_request(self->service));
}

struct command *make_request_service(int service)
{
  NEW(request_service, closure);

  closure->super.call = do_request_service;
  closure->service = service;

  return &closure->super;
}

/* ;; GABA:
   (class
     (name request_info)
     (vars
       ; Next request
       (next object request_info)
       (want_reply . int)
       ; If true, close the channel if the request fails
       (essential . int)

       (format method "struct lsh_string *" "struct ssh_channel *c")
       ; Called with a success/fail indication
       (result method int "struct ssh_channel *c" int)))
*/

#define REQUEST_FORMAT(r, c) ((r)->format((r), (c)))
#define REQUEST_RESULT(r, c, i) ((r)->result((r), (c), (i)))

/* Initiate and manage a session */
/* GABA:
   (class
     (name client_session)
     (super ssh_channel)
     (vars
       ; Exec or shell request. 
       ;(final_request simple int)
       ;(args string)

       ; List of requests
       (requests object request_info)
  
       ; To access stdio
       (in object io_fd)
       (out object io_fd)
       (err object io_fd)

       ; Where to save the exit code.
       (exit_status simple "int *")))
*/

/* Callback used when the server sends us eof */
static void
do_client_session_eof(struct ssh_channel *c)
{
  CAST(client_session, session, c);
  
  close_fd(&session->in->super, 0);
#if 0
  close_fd(&session->out->super, 0);
  close_fd(&session->err->super, 0);
#endif
}  

static void
do_client_session_close(struct ssh_channel *c)
{
  static const struct exception finish_exception
    = STATIC_EXCEPTION(EXC_FINISH_PENDING, "Session closed.");

  EXCEPTION_RAISE(c->e, &finish_exception);
}


/* GABA:
   (class
     (name exit_handler)
     (super channel_request)
     (vars
       (exit_status simple "int *")))
*/

static void
do_exit_status(struct channel_request *c,
	       struct ssh_channel *channel,
	       struct ssh_connection *connection UNUSED,
	       int want_reply,
	       struct simple_buffer *args)
{
  CAST(exit_handler, closure, c);
  int status;

  if (!want_reply
      && parse_uint32(args, &status)
      && parse_eod(args))
    {
      *closure->exit_status = status;

      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      /* Send EOF, if we haven't done that already. */
      /* FIXME: Make this behaviour configurable, there may be some
       * child process alive that we could talk to. */

      if (!(channel->flags & CHANNEL_SENT_EOF))
	channel_eof(channel);
    }
  else
    /* Invalid request */
    EXCEPTION_RAISE
      (channel->e,
       make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
			       "Invalid exit-status message"));
}

static void
do_exit_signal(struct channel_request *c,
	       struct ssh_channel *channel,
	       struct ssh_connection *connection UNUSED,
	       int want_reply,
	       struct simple_buffer *args)
{
  CAST(exit_handler, closure, c);

  int signal;
  int core;

  UINT8 *msg;
  UINT32 length;

  UINT8 *language;
  UINT32 language_length;
  
  if (!want_reply
      && parse_uint32(args, &signal)
      && parse_boolean(args, &core)
      && parse_string(args, &length, &msg)
      && parse_string(args, &language_length, &language)
      && parse_eod(args))
    {
      /* FIXME: What exit status should be returned when the remote
       * process dies violently? */

      *closure->exit_status = 7;

      signal = signal_network_to_local(signal);

      werror("%us", length, msg);
      werror("Remote process was killed by %z.%z\n",
	     signal ? STRSIGNAL(signal) : "an unknown signal",
	     core ? "(core dumped remotely)\n": "");

      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      /* Sent EOF, if we haven't done that already. */
      /* FIXME: Make this behaviour configurable, there may be some
       * child process alive that we could talk to. */

      if (!(channel->flags & CHANNEL_SENT_EOF))
	channel_eof(channel);
    }
  else
    /* Invalid request */
    EXCEPTION_RAISE
      (channel->e,
       make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
			       "Invalid exit-signal message"));
}

struct channel_request *make_handle_exit_status(int *exit_status)
{
  NEW(exit_handler, self);

  self->super.handler = do_exit_status;

  self->exit_status = exit_status;

  return &self->super;
}

struct channel_request *make_handle_exit_signal(int *exit_status)
{
  NEW(exit_handler, self);

  self->super.handler = do_exit_signal;

  self->exit_status = exit_status;

  return &self->super;
}

/* Receive channel data */
static void
do_receive(struct ssh_channel *c,
	   int type, struct lsh_string *data)
{
  CAST(client_session, closure, c);
  
  switch(type)
    {
    case CHANNEL_DATA:
      A_WRITE(&closure->out->write_buffer->super, data, c->e);
      break;
    case CHANNEL_STDERR_DATA:
      A_WRITE(&closure->err->write_buffer->super, data, c->e);
      break;
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static void do_send(struct ssh_channel *c)
{
  CAST(client_session, closure, c);

  assert(closure->in->super.read);

  closure->in->super.want_read = 1;
}

/* We have a remote shell */
static void
do_client_io(struct command *s UNUSED,
	     struct lsh_object *x,
	     struct command_continuation *c,
	     struct exception_handler *e UNUSED)

{
  assert(x);
#if 0
  if (!x)
    {
      werror("do_client_io: Starting shell failed.\n");
      return LSH_CHANNEL_CLOSE | LSH_FAIL;
    }
  else
#endif
    {
      CAST(client_session, session, x);
      struct ssh_channel *channel = &session->super;

      channel->receive = do_receive;
  
      session->out->super.close_callback
	= session->err->super.close_callback = make_channel_close(channel);
  
      session->in->super.read = make_channel_read_data(channel);
      channel->send = do_send;

      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS,
		make_handle_exit_status(session->exit_status));
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL,
		make_handle_exit_signal(session->exit_status));

      channel->eof = do_client_session_eof;
      
      COMMAND_RETURN(c, channel);
    }
}

struct command client_io =
{ STATIC_HEADER, do_client_io };


struct ssh_channel *make_client_session(struct io_fd *in,
					struct io_fd *out,
					struct io_fd *err,
					UINT32 max_window,
					int *exit_status)
{
  NEW(client_session, self);

  init_channel(&self->super);

  /* Makes sure the pending_close bit is set whenever this session
   * dies, no matter when or how. */
  self->super.close = do_client_session_close;
  
  self->super.max_window = max_window;
  self->super.rec_window_size = max_window;

  /* FIXME: Make maximum packet size configurable */
  self->super.rec_max_packet = SSH_MAX_PACKET;

  self->super.request_types = make_alist(0, -1);

  /* self->expect_close = 0; */
  self->in = in;
  self->out = out;
  self->err = err;

  /* Flow control */
  out->write_buffer->report = &self->super.super;
  err->write_buffer->report = &self->super.super;
  
  self->exit_status = exit_status;
  
  return &self->super;
}

/* GABA:
   (class
     (name session_open_command)
     (super channel_open_command)
     (vars
       ; This command can only be executed once,
       ; so we can allocate the session object in advance.
       (session object ssh_channel)))
*/

static struct ssh_channel *
new_session(struct channel_open_command *s,
	    struct ssh_connection *connection,
	    struct lsh_string **request)
{
  CAST(session_open_command, self, s);
  struct ssh_channel *res;

  self->session->write = connection->write;
  
  *request = prepare_channel_open(connection->table, ATOM_SESSION,
				  self->session, "");
  if (!*request)
    return NULL;
  
  res = self->session;

  /* Make sure this command can not be invoked again */
  self->session = NULL;

  return res;
}

struct command *make_open_session_command(struct ssh_channel *session)
{
  NEW(session_open_command, self);
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_session;
  self->session = session;

  return &self->super.super;
}


static struct lsh_string *
do_format_shell_request(struct channel_request_command *s UNUSED,
			struct ssh_channel *channel,
			struct command_continuation **c)
{
  return format_channel_request(ATOM_SHELL, channel, !!*c, "");
}

struct channel_request_command request_shell =
{ { STATIC_HEADER, do_channel_request_command }, do_format_shell_request };

