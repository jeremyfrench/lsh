/* server.c
 *
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "server.h"

#include "abstract_io.h"
#include "channel.h"
#include "connection.h"
#include "debug.h"
#include "format.h"
#include "keyexchange.h"
#include "read_line.h"
#include "read_packet.h"
#include "reaper.h"
#include "ssh.h"
#include "translate_signal.h"
#include "unpad.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#ifndef _GNU_SOURCE
#warning _GNU_SOURCE undefined
#endif

#include <assert.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

struct server_callback
{
  struct fd_callback super;
  struct io_backend *backend;

  struct signer *secret;        /* secret key */
  struct lsh_string *host_key;  /* public key */
  UINT32 block_size;
  char *id_comment;

  struct randomness *random;
  struct make_kexinit *init;
  struct packet_handler *kexinit_handler;
};

static int server_initiate(struct fd_callback **c,
			   int fd)
{
  struct server_callback *closure = (struct server_callback *) *c;
  
  struct ssh_connection *connection
    = make_ssh_connection(closure->kexinit_handler);

  int res;
  
  verbose("server_initiate()\n");

  connection_init_io(connection,
		     io_read_write(closure->backend, fd,
				   make_server_read_line(connection),
				   closure->block_size,
				   make_server_close_handler()),
		     closure->random);

  
  connection->server_version
    = ssh_format("SSH-%lz-%lz %lz",
		 PROTOCOL_VERSION,
		 SOFTWARE_SERVER_VERSION,
		 closure->id_comment);

  res = A_WRITE(connection->raw,
		 ssh_format("%lS\r\n", connection->server_version));
  if (LSH_CLOSEDP(res))
    return res;

  return res | initiate_keyexchange(connection, CONNECTION_SERVER,
				    MAKE_KEXINIT(closure->init),
				    NULL);
}

struct server_line_handler
{
  struct line_handler super;
  struct ssh_connection *connection;
};

static struct read_handler *do_line(struct line_handler **h,
				    UINT32 length,
				    UINT8 *line)
{
  struct server_line_handler *closure = (struct server_line_handler *) *h;
  
  MDEBUG(closure);
  
  if ( (length >= 4) && !memcmp(line, "SSH-", 4))
    {
      /* Parse and remember format string */
      if ((length >= 8) && !memcmp(line + 4, "2.0-", 4))
	{
	  struct read_handler *new = make_read_packet
	    (make_packet_unpad
	     (make_packet_debug(&closure->connection->super,
				"recieved")),
	     closure->connection);
	  
	  closure->connection->client_version
	    = ssh_format("%ls", length, line);

	  verbose("Client version: ");
	  verbose_safe(closure->connection->client_version->length,
		       closure->connection->client_version->data);
	  verbose("\n");
	  
	  /* FIXME: Cleanup properly. */
	  lsh_object_free(closure);

	  return new;
	}
      else
	{
	  werror("Unsupported protocol version: ");
	  werror_safe(length, line);
	  werror("\n");

	  /* FIXME: Clean up properly */
	  lsh_object_free(closure);
	  *h = 0;
		  
	  return 0;
	}
    }
  else
    {
      /* Display line */
      werror_safe(length, line);

      /* Read next line */
      return 0;
    }
}

struct read_handler *make_server_read_line(struct ssh_connection *c)
{
  struct server_line_handler *closure;

  NEW(closure);
  
  closure->super.handler = do_line;
  closure->connection = c;
  
  return make_read_line(&closure->super);
}

struct fd_callback *
make_server_callback(struct io_backend *b,
		     char *comment,
		     UINT32 block_size,
		     struct randomness *random,
		     struct make_kexinit *init,
		     struct packet_handler *kexinit_handler)
{
  struct server_callback *connected;

  NEW(connected);

  connected->super.f = server_initiate;
  connected->backend = b;
  connected->block_size = block_size;
  connected->id_comment = comment;

  connected->random = random;  
  connected->init = init;
  connected->kexinit_handler = kexinit_handler;
  
  return &connected->super;
}

static int server_die(struct close_callback *closure, int reason)
{
  verbose("Connection died, for reason %d.\n", reason);
  if (reason != CLOSE_EOF)
    werror("Connection died.\n");

  return 0;  /* Ignored */
}

struct close_callback *make_server_close_handler(void)
{
  struct close_callback *c;

  NEW(c);

  c->f = server_die;

  return c;
}

/* Session */
struct server_session
{
  struct ssh_channel super;

  /* User information */
  struct unix_user *user;

  /* Non-zero if a shell or command has been started. */
  int running;

  /* Child process's stdio */
  struct io_fd *in;
  struct io_fd *out;
  struct io_fd *err;
};

/* Recieve channel data */
static int do_recieve(struct ssh_channel *c,
		      int type, struct lsh_string *data)
{
  struct server_session *closure = (struct server_session *) c;
  
  MDEBUG(closure);

  switch(type)
    {
    case CHANNEL_DATA:
      return A_WRITE(&closure->in->buffer->super, data);
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      return LSH_OK | LSH_GOON;
    default:
      fatal("Internal error!\n");
    }
}

/* We may send more data */
static int do_send(struct ssh_channel *c)
{
  struct server_session *closure = (struct server_session *) c;

  MDEBUG(closure);

  closure->out->on_hold = 0;
  closure->err->on_hold = 0;
  
  return LSH_OK | LSH_GOON;
}

struct ssh_channel *make_server_session(struct unix_user *user,
					UINT32 max_window,
					struct alist *request_types)
{
  struct server_session *self;

  NEW(self);

  init_channel(&self->super);

  self->super.max_window = max_window;
  self->super.rec_window_size = max_window;

  /* FIXME: Make maximum packet size configurable. */
  self->super.rec_max_packet = SSH_MAX_PACKET;

  self->super.request_types = request_types;
  self->user = user;

  self->running = 0;

  self->in = NULL;
  self->out = NULL;
  self->err = NULL;
  
  return &self->super;
}

struct open_session
{
  struct channel_open super;

  struct unix_user *user;
  struct alist *session_requests;
};

#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

static struct ssh_channel *do_open_session(struct channel_open *c,
					   struct simple_buffer *args,
					   UINT32 *error,
					   char **error_msg,
					   struct lsh_string **data)
{
  struct open_session *closure = (struct open_session *) c;
  
  MDEBUG(closure);

  debug("server.c: do_open_session()\n");
  
  if (!parse_eod(args))
    return 0;
  
  return make_server_session(closure->user, WINDOW_SIZE,
			     closure->session_requests);
}

struct channel_open *make_open_session(struct unix_user *user,
				       struct alist *session_requests)
{
  struct open_session *closure;

  NEW(closure);

  closure->super.handler = do_open_session;
  closure->user = user;
  closure->session_requests = session_requests;
  
  return &closure->super;
}

struct server_connection_service
{
  struct unix_service super;

  struct alist *global_requests;

  /* Requests specific to session channels */
  struct alist *session_requests; 

  /* FIXME: Doesn't support any channel types but "session".
   * This must be fixed to support for "direct-tcpip" channels. */
};

/* Start an authenticated ssh-connection service */
static struct ssh_service *do_login(struct unix_service *c,
				    struct unix_user *user)
{
  struct server_connection_service *closure
    = (struct server_connection_service *) c;

  MDEBUG(closure);

  debug("server.c: do_login()\n");
  
  return
    make_connection_service(closure->global_requests,
			    make_alist(1, ATOM_SESSION,
				       make_open_session(user,
							 closure->session_requests),
				       -1),
			    NULL);
}

struct unix_service *make_server_session_service(struct alist *global_requests,
						 struct alist *session_requests)
{
  struct server_connection_service *closure;

  NEW(closure);

  closure->super.login = do_login;
  closure->global_requests = global_requests;
  closure->session_requests = session_requests;
  
  return &closure->super;
}

struct lsh_string *format_exit_signal(struct ssh_channel *channel,
				      int core, int signal)
{
  struct lsh_string *msg = ssh_format("Process killed by %z.", strsignal(signal));
  
  return format_channel_request(ATOM_EXIT_SIGNAL,
				channel,
				0,
				"%i%c%fS%z",
				signal_local_to_network(signal),
				core,
				msg, "");
}

struct lsh_string *format_exit(struct ssh_channel *channel, int value)
{
  return format_channel_request(ATOM_EXIT_STATUS,
				channel,
				0,
				"%i", value);
}
      
struct exit_shell
{
  struct exit_callback super;

  struct server_session *session;
};

static void do_exit_shell(struct exit_callback *c, int signaled,
			  int core, int value)
{
  struct exit_shell *closure = (struct exit_shell *) c;
  struct server_session *session = closure->session;
  struct ssh_channel *channel = &session->super;
  
  MDEBUG(closure);
  MDEBUG(session);
  
  close_fd(session->in);
  close_fd(session->out);
  close_fd(session->err);
  
  if (!(channel->flags & CHANNEL_SENT_EOF)
      /* Don't send eof if the process died violently. */
      && !signaled)
    {
      int res = channel_eof(channel);
      if (LSH_CLOSEDP(res))
	/* FIXME: Can we do anything better with the return code than
	 * ignore it? */
	return;
    }

  if (!(channel->flags & CHANNEL_SENT_CLOSE))
    {
      int res = A_WRITE(channel->write,
			signaled
			? format_exit_signal(channel, core, value)
			: format_exit(channel, value));
      res = channel_close(channel);
      /* FIXME: Can we do anything better with the return code than
       * ignore it? */
      
      return;
    }
}

static struct exit_callback *make_exit_shell(struct server_session *session)
{
  struct exit_shell *self;

  NEW(self);

  self->super.exit = do_exit_shell;
  self->session = session;

  return &self->super;
}

struct shell_request
{
  struct channel_request super;

  struct io_backend *backend;
  struct reap *reap;
};

/* Creates a one-way socket connection. Returns 1 on successm 0 on
 * failure. fds[0] is for reading, fds[1] for writing (like for the
 * pipe() system call). */
static int make_pipe(int *fds)
{
  /* From the shutdown(2) man page */
#define REC 0
#define SEND 1

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      werror("socketpair() failed: %s\n", strerror(errno));
      return 0;
    }
  debug("Created socket pair. Using fd:s %d <-- %d\n", fds[0], fds[1]);

  if(shutdown(fds[0], SEND) < 0)
    {
      werror("shutdown(%d, SEND) failed: %s\n", fds[0], strerror(errno));
      return 0;
    }
  if (shutdown(fds[1], REC) < 0)
    {
      werror("shutdown(%d, SEND) failed: %s\n", fds[0], strerror(errno));
      return 0;
    }
  return 1;
}

static char *make_env_pair(char *name, struct lsh_string *value)
{
  return ssh_format("%z=%lS%c", name, value, 0)->data;
}

static char *make_env_pair_c(char *name, char *value)
{
  return ssh_format("%z=%z%c", name, value, 0)->data;
}

static int do_spawn_shell(struct channel_request *c,
			  struct ssh_channel *channel,
			  int want_reply,
			  struct simple_buffer *args)
{
  struct shell_request *closure = (struct shell_request *) c;
  struct server_session *session = (struct server_session *) channel;

  int in[2];
  int out[2];
  int err[2];

  MDEBUG(closure);
  MDEBUG(session);

  if (!parse_eod(args))
    return LSH_FAIL | LSH_DIE;

  if (session->running)
    /* Already spawned a shell or command */
    goto fail;
  
  /* {in|out|err}[0] is for reading,
   * {in|out|err}[1] for writing. */

  if (make_pipe(in))
    {
      if (make_pipe(out))
	{
	  if (make_pipe(err))
	    {
	      pid_t child;
	      
	      switch(child = fork())
		{
		case -1:
		  werror("fork() failed: %s\n", strerror(errno));
		  /* Close and return channel_failure */
		  break; 
		case 0:
		  /* Child */
		  debug("do_spawn_shell: Child process\n");
		  
		  if (!session->user->shell)
		    {
		      werror("No login shell!\n");
		      exit(EXIT_FAILURE);
		    }
		      
		  if (getuid() != session->user->uid)
		    if (!change_uid(session->user))
		      {
			werror("Changing uid failed!\n");
			exit(EXIT_FAILURE);
		      }
		  
		  assert(getuid() == session->user->uid);

		  if (!change_dir(session->user))
		    {
		      werror("Could not change to home (or root) directory!\n");
		      exit(EXIT_FAILURE);
		    }

		  /* Close all descriptors but those used for
		   * communicationg with parent. We rely on the
		   * close-on-exec flag for all fd:s handled by the
		   * backend. */

		  close(STDIN_FILENO);
		  if (dup2(in[0], STDIN_FILENO) < 0)
		    {
		      werror("Can't dup stdin!\n");
		      exit(EXIT_FAILURE);
		    }
		  close(in[0]);
		  close(in[1]);

		  close(STDOUT_FILENO);
		  if (dup2(out[1], STDOUT_FILENO) < 0)
		    {
		      werror("Can't dup stdout!\n");
		      exit(EXIT_FAILURE);
		    }
		  close(out[0]);
		  close(out[1]);

		  close(STDERR_FILENO);
		  if (dup2(err[1], STDERR_FILENO) < 0)
		    {
		      /* Can't write any message to stderr. */ 
		      exit(EXIT_FAILURE);
		    }
		  close(err[0]);
		  close(err[1]);

		  {
		    char *shell = session->user->shell->data;
#define MAX_ENV 7
		    char *env[MAX_ENV];
		    char *tz = getenv("TZ");
		    int i = 0;

		    env[i++] = make_env_pair("LOGNAME", session->user->name);
		    env[i++] = make_env_pair("USER", session->user->name);
		    env[i++] = make_env_pair("SHELL", session->user->shell);
		    if (session->user->home)
		      env[i++] = make_env_pair("HOME", session->user->home);
		    if (tz)
		      env[i++] = make_env_pair_c("TZ", tz);

		    /* FIXME: The value of $PATH should not be hard-coded */
		    env[i++] = "PATH=/bin:/usr/bin";
		    env[i++] = NULL;
		    
		    assert(i <= MAX_ENV);

		    if (execle(shell, shell, NULL, env) < 0)
		      exit(EXIT_FAILURE);
#undef MAX_ENV
		  }
		default:
		  /* Parent */

		  debug("Parent process\n");

		  REAP(closure->reap, child, make_exit_shell(session));
		  
		  /* Close the child's fd:s */
		  close(in[0]);
		  close(out[1]);
		  close(err[1]);

		  session->in
		    = io_write(closure->backend, in[1],
				SSH_MAX_PACKET,
				/* FIXME: Use a proper close callback */
				make_channel_close(channel));
		  session->out
		    = io_read(closure->backend, out[0],
			      make_channel_read_data(channel),
			      NULL);
		  session->err
		    = io_read(closure->backend, err[0],
			      make_channel_read_stderr(channel),
			      NULL);

		  channel->recieve = do_recieve;
		  channel->send = do_send;
		  
		  session->running = 1;
		  return want_reply
		    ? A_WRITE(channel->write,
			      format_channel_success(channel->channel_number))
		    : LSH_OK | LSH_GOON;
		  
		}
	      close(err[0]);
	      close(err[1]);
	    }
	  close(out[0]);
	  close(out[1]);
	}
      close(in[0]);
      close(in[1]);
    }
 fail:
  return want_reply
    ? A_WRITE(channel->write, format_channel_failure(channel->channel_number))
    : LSH_OK | LSH_GOON;
}

struct channel_request *make_shell_handler(struct io_backend *backend,
					   struct reap *reap)
{
  struct shell_request *closure;

  NEW(closure);
  closure->super.handler = do_spawn_shell;
  closure->backend = backend;
  closure->reap = reap;
  
  return &closure->super;
}

