/* client.c
 *
 * $Id$ */

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

#include "client.h"

#include "abstract_io.h"
#include "channel.h"
#include "channel_commands.h"
#include "connection.h"
#include "format.h" 
#include "pad.h"
#include "parse.h"
#include "ssh.h"
#include "translate_signal.h"
#include "werror.h"
#include "xalloc.h"

#include <signal.h>

#include <string.h>
#include <assert.h>

#define GABA_DEFINE
#include "client.h.x"
#undef GABA_DEFINE

#include "client.c.x"

static struct lsh_string *
format_service_request(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_REQUEST, name);
}

/* Start a service that the server has accepted (for instance
 * ssh-userauth). */
/* GABA:
   (class
     (name accept_service_handler)
     (super packet_handler)
     (vars
       (service . int)
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
  unsigned msg_number;
  int name;

  simple_buffer_init(&buffer, packet->length, packet->data);
  
  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_ACCEPT)
      && (
#if DATAFELLOWS_WORKAROUNDS
	  (connection->peer_flags & PEER_SERVICE_ACCEPT_KLUDGE)
#else
	  0
#endif
	  || (parse_atom(&buffer, &name)
	      && (name == closure->service)))
      && parse_eod(&buffer))
    {
      lsh_string_free(packet);
      connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = &connection_fail_handler;
      
      COMMAND_RETURN(closure->c, connection);
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(closure->e, "Invalid SSH_MSG_SERVICE_ACCEPT message");
    }
}

struct packet_handler *
make_accept_service_handler(UINT32 service,
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

void
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

struct command *
make_request_service(int service)
{
  NEW(request_service, closure);

  closure->super.call = do_request_service;
  closure->service = service;

  return &closure->super;
}


/* GABA:
   (class
     (name exit_handler)
     (super channel_request)
     (vars
       (exit_status . "int *")))
*/

static void
do_exit_status(struct channel_request *c,
	       struct ssh_channel *channel,
	       struct ssh_connection *connection UNUSED,
	       UINT32 type UNUSED,
	       int want_reply,
	       struct simple_buffer *args,
	       struct command_continuation *s,
	       struct exception_handler *e)
{
  CAST(exit_handler, closure, c);
  UINT32 status;

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

      channel_eof(channel);
      COMMAND_RETURN(s, NULL);
    }
  else
    /* Invalid request */
    PROTOCOL_ERROR(e, "Invalid exit-status message");
}

static void
do_exit_signal(struct channel_request *c,
	       struct ssh_channel *channel,
	       struct ssh_connection *connection UNUSED,
	       UINT32 type UNUSED,
 	       int want_reply,
	       struct simple_buffer *args,
	       struct command_continuation *s,
	       struct exception_handler *e)
{
  CAST(exit_handler, closure, c);

  UINT32 signal;
  int core;

  const UINT8 *msg;
  UINT32 length;

  const UINT8 *language;
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

      werror("%ups", length, msg);
      werror("Remote process was killed by %z.%z\n",
	     signal ? STRSIGNAL(signal) : "an unknown signal",
	     core ? "(core dumped remotely)\n": "");

      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      /* Sent EOF, if we haven't done that already. */
      /* FIXME: Make this behaviour configurable, there may be some
       * child process alive that we could talk to. */

      channel_eof(channel);
      COMMAND_RETURN(s, NULL);
    }
  else
    /* Invalid request */
    PROTOCOL_ERROR(e, "Invalid exit-signal message");
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
     (super channel_open_command)
     (vars
       ; This command can only be executed once,
       ; so we can allocate the session object in advance.
       (session object ssh_channel)))
*/

static struct ssh_channel *
new_session(struct channel_open_command *s,
	    struct ssh_connection *connection,
	    UINT32 local_channel_number,
	    struct lsh_string **request)
{
  CAST(session_open_command, self, s);
  struct ssh_channel *res;

  self->session->write = connection->write;
  
  *request = format_channel_open(ATOM_SESSION,
				 local_channel_number,
				 self->session, "");
  
  res = self->session;

  /* Make sure this command can not be invoked again */
  self->session = NULL;

  return res;
}

struct command *
make_open_session_command(struct ssh_channel *session)
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


/* GABA:
   (class
     (name exec_request)
     (super channel_request_command)
     (vars
       (command string)))
*/

static struct lsh_string *
do_format_exec_request(struct channel_request_command *s,
		       struct ssh_channel *channel,
		       struct command_continuation **c)
{
  CAST(exec_request, self, s);

  verbose("lsh: Requesting remote exec.\n");

  return format_channel_request(ATOM_EXEC, channel,
				!!*c, "%S", self->command);
}

struct command *
make_exec_request(struct lsh_string *command)
{
  NEW(exec_request, req);

  req->super.format_request = do_format_exec_request;
  req->super.super.call = do_channel_request_command;
  req->command = command;

  return &req->super.super;
}

#if 0
/* ;; GABA:
   (class
     (name client_options)
     (vars
       (backend object io_backend)

       ; For i/o exceptions 
       (handler object exception_handler)

       (tty object interactive)
       
       ; -1 means default behaviour
       (with_pty . int)
       
       ; Session modifiers
       (stdin_file . "const char *")
       (stdout_file . "const char *")
       (stderr_file . "const char *")

       ; True if the process's stdin or pty (respectively) has been used. 
       (used_stdin . int)
       (used_pty . int)
       (actions struct object_queue)))

*/

static struct client_options *
make_client_options(void)
{
  return NULL;
}

/* Create a session object. stdout and stderr are shared (although
 * with independent lsh_fd objects). stdin can be used by only one
 * session (until something "session-control"/"job-control" is added).
 * */
static struct ssh_channel *
make_lsh_session(struct client_options *self)
{
  int in;
  int out;
  int err;

  if (self->stdin_file)
    in = open(self->stdin_file, O_RDONLY);
  else
    {
      if (self->used_stdin)
	in = open("/dev/null", O_RDONLY);
      else
	{
	  in = dup(STDIN_FILENO);
	  self->used_stdin = 1;
	}
    }
    
  if (in < 0)
    {
      werror("client.c: Can't dup/open stdin (errno = %i): %z!\n",
	     errno, strerror(errno));
      return NULL;
    }

  out = (self->stdout_file
	 ? open(self->stdout_file, O_WRONLY | O_CREAT, 0666)
	 : dup(STDOUT_FILENO));
  if (out < 0)
    {
      werror("lsh: Can't dup/open stdout (errno = %i): %z!\n",
	     errno, strerror(errno));
      close(in);
      return NULL;
    }

  if (self->stderr_file)
    err = open(self->stderr_file, O_WRONLY | O_CREAT, 0666);
  else
    {
      err = dup(STDERR_FILENO);
      set_error_stream(STDERR_FILENO, 1);
    }

  if (err < 0) 
    {
      werror("client.c: Can't dup/open stderr!\n");
      close(in);
      close(out);
      return NULL;
    }

  /* Clear options */
  self->stdin_file = self->stdout_file = self->stderr_file = NULL;
  
  return make_client_session
    (io_read(make_lsh_fd(self->backend, in, self->handler),
	     NULL, NULL),
     io_write(make_lsh_fd(self->backend, out, self->handler),
	      BLOCK_SIZE, NULL),
     io_write(make_lsh_fd(self->backend, err, self->handler),
	      BLOCK_SIZE, NULL),
     WINDOW_SIZE,
     self->exit_code);
}

/* Create an interactive session */
static struct command *
client_shell_session(struct client_options *self)
{
  struct command *get_pty = NULL;
  struct command *get_shell;
  
  struct object_list *session_requests;
  struct ssh_channel *session = make_lsh_session(self);

  if (!session)
    return NULL;
  
#if WITH_PTY_SUPPORT
  if (self->with_pty && !self->used_pty)
    {
      self->used_pty = 1;

      if (self->tty && INTERACT_IS_TTY(self->tty))
	{
	  if (! (remember_tty(tty_fd)
		 && (get_pty = make_pty_request(tty_fd))))
	    {
	      werror("lsh: Can't use tty (probably getattr or atexit() failed.\n");
	    }
	}
      else
	{
	  werror("client.c: No tty available.\n");
	}
      
    }

  get_shell = make_lsh_start_session(&request_shell.super);
  
  /* FIXME: We need a non-varargs constructor for lists. */
  if (get_pty)
    session_requests
      = make_object_list(2,
			 /* Ignore EXC_CHANNEL_REQUEST for the pty allocation call. */
			 make_catch_apply
			 (make_catch_handler_info(EXC_ALL, EXC_CHANNEL_REQUEST,
						  0, NULL),
			  get_pty),
			 get_shell, -1);
  else
#endif /* WITH_PTY_SUPPORT */
    session_requests = make_object_list(1, get_shell, -1);

  {
    CAST_SUBTYPE(command, r,
		 make_start_session
		 (make_open_session_command(session), session_requests));
    return r;
  }
}
#endif
