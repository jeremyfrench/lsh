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
#include "connection.h"
#include "crypto.h"
#include "debug.h"
#include "encrypt.h"
#include "format.h"
#include "pad.h"
#include "parse.h"
#include "read_line.h"
#include "read_packet.h"
#include "service.h"
#include "ssh.h"
#include "translate_signal.h"
#include "tty.h"
#include "unpad.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"
#include "compress.h"

#include <string.h>
#include <assert.h>

#include "client.c.x"

/* Handle connection and initial handshaking. */
/* GABA:
   (class
     (name client_callback)
     (super fd_callback)
     (vars
       (backend object io_backend)
       (block_size simple UINT32)
       (id_comment simple "const char *")
       (random object randomness)
       (init object make_kexinit)
       (kexinit_handler object packet_handler)))
*/

static int client_initiate(struct fd_callback **c,
			   int fd)
{
  CAST(client_callback, *closure, *c);

  int res;
  
  struct ssh_connection *connection
    = make_ssh_connection(closure->kexinit_handler);

  connection_init_io(connection,
		     &io_read_write(closure->backend, fd,
				    make_client_read_line(connection),
				    closure->block_size,
				    make_client_close_handler())
		     ->buffer->super,
		     closure->random);
  
  connection->versions[CONNECTION_CLIENT]
    = ssh_format("SSH-%lz-%lz %lz",
		 CLIENT_PROTOCOL_VERSION,
		 SOFTWARE_CLIENT_VERSION,
		 closure->id_comment);
  
  res = A_WRITE(connection->raw,
		ssh_format("%lS\r\n",
			   connection->versions[CONNECTION_CLIENT]));
  if (LSH_CLOSEDP(res))
    return res;

  return res | initiate_keyexchange(connection, CONNECTION_CLIENT,
				    MAKE_KEXINIT(closure->init),
				    NULL);
}

/* GABA:
   (class
     (name client_line_handler)
     (super line_handler)
     (vars
       (connection object ssh_connection)))
*/

static int do_line(struct line_handler **h,
		   struct read_handler **r,
		   UINT32 length,
		   UINT8 *line)
{
  CAST(client_line_handler, closure, *h);

  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ( ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	   || ((length >= 9) && !memcmp(line + 4, "1.99-", 5)))
	{
	  struct read_handler *new = 
	    make_read_packet(
	      make_packet_unpad(
	        make_packet_inflate(
	          make_packet_debug(&closure->connection->super, ""),
	          closure->connection
		  )
		),
	      closure->connection
	      );
	  
	  closure->connection->versions[CONNECTION_SERVER]
	    = ssh_format("%ls", length, line);

	  verbose("Client version: %ps\n"
		  "Server version: %ps\n",
		  closure->connection->versions[CONNECTION_CLIENT]->length,
		  closure->connection->versions[CONNECTION_CLIENT]->data,
		  closure->connection->versions[CONNECTION_SERVER]->length,
		  closure->connection->versions[CONNECTION_SERVER]->data);
	  
	  /* FIXME: Cleanup properly. */
	  KILL(closure);

	  *r = new;
	  return LSH_OK | LSH_GOON;
	}
      else
	{
	  werror("Unsupported protocol version: %ps\n",
		 length, line);

	  /* FIXME: Clean up properly */
	  KILL(closure);
	  *h = NULL;
		  
	  return LSH_FAIL | LSH_DIE;
	}
    }
  else
    {
      /* Display line */
      werror("%ps\n", length, line);

      /* Read next line */
      return LSH_OK | LSH_GOON;
    }
}

struct read_handler *make_client_read_line(struct ssh_connection *c)
{
  NEW(client_line_handler, closure);

  closure->super.handler = do_line;
  closure->connection = c;
  
  return make_read_line(&closure->super);
}
  
struct fd_callback *
make_client_callback(struct io_backend *b,
		     const char *comment,
		     UINT32 block_size,
		     struct randomness *random,
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler)
  
{
  NEW(client_callback, connected);

  connected->super.f = client_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  connected->id_comment = comment;

  connected->random = random;
  connected->init = init;
  connected->kexinit_handler = kexinit_handler;

  return &connected->super;
}

static int client_close_die(struct close_callback *closure UNUSED,
			    int reason)
{
  verbose("Connection died, for reason %i.\n", reason);
  if (reason != CLOSE_EOF)
    werror("Connection died.\n");

  /* FIXME: Return value is not used. */
  return 4711;
}

struct close_callback *make_client_close_handler(void)
{
  NEW(close_callback, c);

  c->f = client_close_die;

  return c;
}

/* Start a service that the server has accepted (for instance ssh-userauth). */
/* GABA:
   (class
     (name accept_service_handler)
     (super packet_handler)
     (vars
       (service_name simple int)
       (service object ssh_service)))
*/

static int do_accept_service(struct packet_handler *c,
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
      && (name == closure->service_name))
    {
      lsh_string_free(packet);
      connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = connection->fail;
      
      return SERVICE_INIT(closure->service, connection);
    }

  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

struct packet_handler *make_accept_service_handler(int service_name,
						   struct ssh_service *service)
{
  NEW(accept_service_handler, closure);

  closure->super.handler = do_accept_service;
  closure->service_name = service_name;
  closure->service = service;

  return &closure->super;
}

/* GABA:
   (class
     (name service_request)
     (super ssh_service)
     (vars
       (service_name simple int)
       (service object ssh_service)))
*/

static int do_request_service(struct ssh_service *c,
			      struct ssh_connection *connection)
{
  CAST(service_request, closure, c);
  
  connection->dispatch[SSH_MSG_SERVICE_ACCEPT]
    = make_accept_service_handler(closure->service_name,
				  closure->service);
  
  return A_WRITE(connection->write, format_service_request(closure->service_name));
}

struct ssh_service *request_service(int service_name,
				    struct ssh_service *service)
{
  NEW(service_request, closure);

  closure->super.init = do_request_service;
  closure->service_name = service_name;
  closure->service = service;

  return &closure->super;
}

/* GABA:
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
static int close_client_session(struct ssh_channel *c)
{
  CAST(client_session, session, c);
  
  close_fd(&session->in->super, 0);
#if 0
  close_fd(&session->out->super, 0);
  close_fd(&session->err->super, 0);
#endif

  /* The LSH_CHANNEL_PENDING_CLOSE should action should be invoked
   * immediately when the channel is opened. */
  return LSH_OK /* | LSH_CHANNEL_PENDING_CLOSE */;
}  

static int client_session_die(struct ssh_channel *c)
{
  CAST(client_session, closure, c);
  
  /* FIXME: Don't die this hard. */
  if ( (closure->super.flags & (CHANNEL_SENT_CLOSE | CHANNEL_RECEIVED_CLOSE))
       ==  (CHANNEL_SENT_CLOSE | CHANNEL_RECEIVED_CLOSE))
    exit(EXIT_SUCCESS);

  exit(EXIT_FAILURE);
}

/* GABA:
   (class
     (name exit_handler)
     (super channel_request)
     (vars
       (exit_status simple "int *")))
*/

static int do_exit_status(struct channel_request *c,
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

      /* Sent EOF, if we haven't done that already. */
      /* FIXME: Make this behaviour configurable, there may be some
       * child process alive that we could talk to. */

      if (!(channel->flags & CHANNEL_SENT_EOF))
	return channel_eof(channel);
      
      return LSH_OK | LSH_GOON;
    }
  
  /* Invalid request */
  return LSH_FAIL | LSH_DIE;
}

static int do_exit_signal(struct channel_request *c,
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
	     signal ? strsignal(signal) : "an unknown signal",
	     core ? "(core dumped remotely)\n": "");

      ALIST_SET(channel->request_types, ATOM_EXIT_STATUS, NULL);
      ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL, NULL);

      /* Sent EOF, if we haven't done that already. */
      /* FIXME: Make this behaviour configurable, there may be some
       * child process alive that we could talk to. */

      if (!(channel->flags & CHANNEL_SENT_EOF))
	return channel_eof(channel);

      return LSH_OK | LSH_GOON;
#if 0
      return close_client_session(channel);
#endif
    }
  
  /* Invalid request */
  return LSH_FAIL | LSH_DIE;
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
static int do_receive(struct ssh_channel *c,
		      int type, struct lsh_string *data)
{
  CAST(client_session, closure, c);
  
  switch(type)
    {
    case CHANNEL_DATA:
      return A_WRITE(&closure->out->buffer->super, data);
    case CHANNEL_STDERR_DATA:
      return A_WRITE(&closure->err->buffer->super, data);
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static int do_send(struct ssh_channel *c)
{
  CAST(client_session, closure, c);

  assert(closure->in->super.read);
  assert(closure->in->handler);
  closure->in->super.want_read = 1;

  return LSH_OK | LSH_GOON;
}

/* We have a remote shell */
static int do_io(struct ssh_channel *channel)
{
  CAST(client_session, closure, channel);
  
  channel->receive = do_receive;
  
  closure->out->super.close_callback
    = closure->err->super.close_callback = make_channel_close(channel);
  
  closure->in->handler = make_channel_read_data(&closure->super);
  channel->send = do_send;

  ALIST_SET(channel->request_types, ATOM_EXIT_STATUS,
	    make_handle_exit_status(closure->exit_status));
  ALIST_SET(channel->request_types, ATOM_EXIT_SIGNAL,
	    make_handle_exit_signal(closure->exit_status));

  channel->eof = close_client_session;

  return LSH_OK | LSH_CHANNEL_READY_SEND;
}

static struct request_info *skip_silent_requests(struct request_info *req)
{
  while (req && !req->want_reply)
    req = req->next;

  return req;
}

static int do_channel_success(struct ssh_channel *c);
static int do_channel_failure(struct ssh_channel *c);

static void install_request_handler(struct client_session *session,
				   struct request_info *req)
{
  session->requests = skip_silent_requests(req);

  if (session->requests)
    {
      session->super.channel_success = do_channel_success;
      session->super.channel_failure = do_channel_failure;
    }
  else
    session->super.channel_success = session->super.channel_failure = NULL;
}
  
static int do_channel_success(struct ssh_channel *c)
{
  CAST(client_session, closure, c);
  int res = LSH_OK | LSH_GOON;
  
  assert(closure->requests);
  assert(closure->requests->want_reply);

  if (closure->requests->result)
    res = REQUEST_RESULT(closure->requests, c, 1);

  if (!LSH_FAILUREP(res))
    install_request_handler(closure, closure->requests->next);    

  return res;
}

#if 0
static int do_channel_failure(struct ssh_channel *c)
{
  CAST(client_session, closure, c);
  int res = 0;
  struct request_info *req = closure->requests;
  
  assert(req);
  assert(req->want_reply);

  if (req->result)
    res = REQUEST_RESULT(req, c, 0);

  if (!LSH_FAILUREP(res))
    install_request_handler(closure, req->next);
  
  if (req->essential)
    res |= LSH_CHANNEL_CLOSE;

  return res;
}
  
/* We have opened a channel of type "session" */
static int do_open_confirm(struct ssh_channel *c)
{
  CAST(client_session, closure, c);
  struct request_info *req;
  int res = 0;
  
  closure->super.open_confirm = NULL;
  closure->super.open_failure = NULL;
  
  /* tty_makeraw(0); */

  for (req = closure->requests; req; req = req->next)
    {
      assert(req->want_reply == (req->essential || req->result));
      
      res |= A_WRITE(closure->super.write,
		     REQUEST_FORMAT(req, c));
      if (LSH_CLOSEDP(res))
	return res;
    }

  install_request_handler(closure, closure->requests);

  return res;
}
#endif  

static struct ssh_channel *make_client_session(struct io_fd *in,
					       struct io_fd *out,
					       struct io_fd *err,
					       UINT32 max_window,
					       struct request_info *requests,
					       int *exit_status)
{
  NEW(client_session, self);

  init_channel(&self->super);

  self->super.max_window = max_window;
  self->super.rec_window_size = max_window;

  /* FIXME: Make maximum packet size configurable */
  self->super.rec_max_packet = SSH_MAX_PACKET;

  self->super.request_types = make_alist(0, -1);

  /* self->expect_close = 0; */
  self->in = in;
  self->out = out;
  self->err = err;

  self->requests = requests;

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
       (session object client_session)))
*/

static struct ssh_channel *
new_session(struct channel_open_command *s,
	    struct ssh_connection *connection,
	    struct lsh_string **request)
{
  CAST(session_open_command, self, s);
  struct ssh_channel *res;
  *request = prepare_channel_open(connection->channels, ATOM_SESSION,
				  self->session, "");
  if (!*request)
    return NULL;
  
  res = &self->session->super;

  /* Make sure this command can not be invoked again */
  self->session = NULL;

  return res;
}

struct command *make_open_session_command(struct client_session *session)
{
  NEW(session_open_command, self);
  self->super.super.call = do_channel_open_command;
  self->super.new_channel = new_session;
  self->session = session;
}

/* GABA:
   (class
     (name client_startup)
     (super connection_startup)
     (vars
       (session object ssh_channel)
       
       ; Exec or shell request. 
       ;; (final_request simple int)
       ;; (args string)
  
       ; To access stdio 
       ;; (in object io_fd)
       ;; (out object io_fd)
       ;; (err object io_fd)
       ))
*/

static int do_client_startup(struct connection_startup *c,
			     struct ssh_connection *connection)
{
  CAST(client_startup, closure, c);
  struct lsh_string *s;
  
  closure->session->write = connection->write;
  
  closure->session->open_confirm = do_open_confirm;
  closure->session->open_failure = client_session_die;

  s = prepare_channel_open(connection->channels, ATOM_SESSION,
			   closure->session, "");
  if (!s)
    fatal("Couldn't allocate a channel number!\n");

  /* Close connetion when the last channel is closed. */
  connection->channels->pending_close = 1;
  
  return A_WRITE(connection->write, s);
}

#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

/* Request opening a session. */
struct connection_startup *make_client_startup(struct io_fd *in,
					       struct io_fd *out,
					       struct io_fd *err,
					       struct request_info *requests,
					       int *exit_status)
{
  NEW(client_startup, closure);
  
  closure->super.start = do_client_startup;
  closure->session = make_client_session(in, out, err,
					 WINDOW_SIZE,
					 requests,
					 exit_status);

  return &closure->super;
}

/* FIXME: This should probably move to client_pty */
/* GABA:
   (class
     (name pty_request)
     (super request_info)
     (vars
       ; An open fd connected to a tty (most likely, /dev/tty opened by main).
       (tty . int)
       (ios simple "struct termios")
       (term string)
       (width . UINT32)
       (height . UINT32)
       (width_p . UINT32)
       (height_p . UINT32)
       (modes string)))
*/

#if WITH_PTY_SUPPORT
static struct lsh_string *do_pty_format(struct request_info *r,
					struct ssh_channel *channel)
{
  CAST(pty_request, req, r);

  verbose("lsh: Requesting a remote pty.\n");
  return format_channel_request(ATOM_PTY_REQ, channel, req->super.want_reply, 
				"%S%i%i%i%i%S",
				req->term,
				req->width, req->height,
				req->width_p, req->height_p,
				req->modes);
}

static int do_pty_result(struct request_info *r,
			 struct ssh_channel *ignored UNUSED,
			 int res)
{
  CAST(pty_request, req, r);

  verbose("lsh: pty request %z.\n", res ? "successful" : "failed");
  
  if (res)
    {
      if (!tty_setattr(req->tty, &req->ios))
	werror("do_pty_result: "
	       "Setting the attributes of the local terminal failed.\n");
    }
  return LSH_OK | LSH_GOON;
}

struct request_info *make_pty_request(int fd, int essential, int raw,
				      struct request_info *next)
{
  NEW(pty_request, req);

  char *term = getenv("TERM");

  req->super.next = next;
  req->super.want_reply = 1;
  req->super.essential = essential;
  req->super.format = do_pty_format;
  
  req->tty = fd;
  req->term = term ? format_cstring(term) : ssh_format("");
  
  if (tty_getattr(fd, &req->ios)
      && tty_getwinsize(fd, &req->width, &req->height,
			&req->width_p, &req->height_p))
    {
      req->modes = tty_encode_term_mode(&req->ios);

      if (raw)
	CFMAKERAW(&req->ios);
        
      req->super.result = do_pty_result;
    }
  else
    req->super.result = NULL;

  return &req->super;
}
#endif / !WITH_PTY_SUPPORT */

static struct lsh_string *do_shell_format(struct request_info *req,
					 struct ssh_channel *channel)
{
  return format_channel_request(ATOM_SHELL, channel, req->want_reply, "");
}

static int do_shell_result(struct request_info *ignored UNUSED,
			   struct ssh_channel *channel,
			   int res)
{
  if (res)
    return do_io(channel);
  
  werror("do_shell_result: Starting shell failed.\n");
  return LSH_OK | LSH_GOON;
}

struct request_info *make_shell_request(struct request_info *next)
{
  NEW(request_info, req);
  req->next = next;
  req->essential = 1;
  req->want_reply = 1;
  req->format = do_shell_format;
  req->result = do_shell_result;

  return req;
}


