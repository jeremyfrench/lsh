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
#include "server_pty.h"
#include "ssh.h"
#include "tcpforward.h"
#include "translate_signal.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include <errno.h>

/* For debug */
#include <signal.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#if WITH_UTMP
#if HAVE_UTMP_H
#include <utmp.h>
#endif

#if HAVE_UTMPX_H
#include <utmpx.h>
#endif
#endif /* WITH_UTMP */

/* Socket workround */
#ifndef SHUTDOWN_WORKS_WITH_UNIX_SOCKETS

/* There's an how++ missing in the af_unix shutdown implementation of
 * some linux versions. Try an ugly workaround. */
#ifdef linux

/* From src/linux/include/net/sock.h */
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#undef SHUT_RD
#undef SHUT_WR
#undef SHUT_RD_WR

#define SHUT_RD RCV_SHUTDOWN
#define SHUT_WR SEND_SHUTDOWN
#define SHUT_RD_WR (RCV_SHUTDOWN | SEND_SHUTDOWN)

#else /* !linux */

/* Don't know how to work around the broken shutdown(). So disable it
 * completely. */

#define SHUTDOWN(fd, how) 0

#endif /* !linux */
#endif /* !SHUTDOWN_WORKS_WITH_UNIX_SOCKETS */

#ifndef SHUTDOWN
#define SHUTDOWN(fd, how) (shutdown((fd), (how)))
#endif

#ifndef SHUT_RD
#define SHUT_RD 0
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef SHUT_RD_WR
#define SHUT_RD_WR 2
#endif

#ifndef UT_NAMESIZE
#  define UT_NAMESIZE 8		/* FIXME: sane default value */
#endif

#include "server_session.c.x"

/* GABA:
   (class
     (name process_resource)
     (super resource)
     (vars
       (pid . pid_t)
       ; For utmp/wtmp logging
       (tty string)
       ; Signal used for killing the process.
       (signal . int)))
*/

static void do_kill_process(struct resource *r)
{
  CAST(process_resource, self, r);

  if (self->super.alive)
    {
      self->super.alive = 0;
      /* NOTE: This function only makes one attempt at killing the
       * process. An improvement would be to install a callout handler
       * which will kill -9 the process after a delay, if it hasn't died
       * voluntarily. */
      
      if (kill(self->pid, self->signal) < 0)
	{
	  werror("do_kill_process: kill() failed (errno = %i): %z\n",
		 errno, STRERROR(errno));
	}
#if WITH_UTMP && HAVE_LOGWTMP
      if (self->tty)
	{
#if HAVE_LOGOUT
	  logout(self->tty->data);
#else /* !HAVE_LOGOUT */
	  /* FIXME: Should we pass NULL:s or empty strings for the
	   * ut_name and ut_host fields? */
	  logwtmp(self->tty->data, NULL, NULL);
#endif /* !HAVE_LOGOUT */
	}
#endif /* WITH_UTMP && HAVE_LOGWTMP */
    }
}
          
struct resource *
make_process_resource(pid_t pid, struct lsh_string *tty, int signal)
{
  NEW(process_resource, self);
  self->super.alive = 1;

  self->pid = pid;
  self->tty = tty;
  self->signal = signal;

  self->super.kill = do_kill_process;

  return &self->super;
}

/* Session */
/* GABA:
   (class
     (name server_session)
     (super ssh_channel)
     (vars
       ; User information
       (user object lsh_user)

       (initial_window . UINT32)

       ; Resource to kill when the channel is closed. 
       (process object resource)

       ; pty
       (pty object pty_info)
       ; value of the TERM environment variable
       (term string)

       ; Child process's stdio 
       (in object lsh_fd)
       (out object lsh_fd)
       ;; err may be NULL, if there's no separate stderr channel.
       ;; This happens if we use a pty, and the bash workaround
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

      session->out->want_read = 1;
    }
  
  if (session->err && session->err->super.alive)
    {
      assert(session->err->read);
  
      session->err->want_read = 1;
    }
}

static void
do_eof(struct ssh_channel *channel)
{
  CAST(server_session, session, channel);

  write_buffer_close(session->in->write_buffer);

  if ( (channel->flags & CHANNEL_SENT_EOF)
       && (channel->flags & CHANNEL_CLOSE_AT_EOF))
    channel_close(channel);
}

static void
do_close(struct ssh_channel *c)
{
  CAST(server_session, session, c);

  if (session->process)
    KILL_RESOURCE(session->process);
}

struct ssh_channel *
make_server_session(struct lsh_user *user,
		    UINT32 initial_window,
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

  self->super.close = do_close;
  
  self->user = user;

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
       (user object lsh_user)
       (session_requests object alist)))
*/

#define WINDOW_SIZE 10000

static void
do_open_session(struct channel_open *s,
		struct ssh_connection *connection UNUSED,
		UINT32 type UNUSED,
		UINT32 send_window_size UNUSED,
		UINT32 send_max_packet UNUSED,
		struct simple_buffer *args,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(open_session, self, s);

  debug("server.c: do_open_session()\n");

  if (parse_eod(args))
    {
      COMMAND_RETURN(c,
		     make_server_session(self->user,
					 WINDOW_SIZE, self->session_requests));
    }
  else
    {
      PROTOCOL_ERROR(e, "trailing garbage in open message");
    }
}

struct channel_open *
make_open_session(struct lsh_user *user,
		  struct alist *session_requests)
{
  NEW(open_session, closure);

  closure->super.handler = do_open_session;
  closure->user = user;
  closure->session_requests = session_requests;
  
  return &closure->super;
}

/* A command taking two arguments: unix_user, connection,
 * returns the connection. */
/* GABA:
   (class
     (name server_connection_service)
     (super command)
     (vars
       ;; (global_requests object alist)

       ; Requests specific to session channels 
       (session_requests object alist)))
*/

/* Start an authenticated ssh-connection service */
static void
do_login(struct command *s,
	 struct lsh_object *x,
	 struct command_continuation *c,
	 struct exception_handler *e UNUSED)
{
  CAST(server_connection_service, closure, s);
  CAST_SUBTYPE(lsh_user, user, x);
  
  werror("User %pS authenticated for ssh-connection service.\n",
	 user->name);

  /* FIXME: It would be better to take one more alists as arguments,
   * and cons the ATOM_SESSION service at the head of it. But that
   * won't work as long as an alist doesn't consist of independent
   * cons-objects. */
  
  COMMAND_RETURN
    (c, make_install_fix_channel_open_handler
     (ATOM_SESSION, make_open_session(user,
				      closure->session_requests)));
  
}

/* FIXME: To make this more flexible, we need to have some argument
 * that lists (i) the channel types we want to support in
 * CHANNEL_OPEN, and (ii) for each channel type, the types of
 * channel_requests we want to support. */
struct command *
make_server_connection_service(struct alist *session_requests)
{
  NEW(server_connection_service, closure);

  closure->super.call = do_login;
  closure->session_requests = session_requests;

  return &closure->super;
}

struct lsh_string *format_exit_signal(struct ssh_channel *channel,
				      int core, int signal)
{
  struct lsh_string *msg = ssh_format("Process killed by %lz.\n",
				      STRSIGNAL(signal));
  
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

/* GABA:
   (class
     (name exit_shell)
     (super exit_callback)
     (vars
       (session object server_session)))
*/

static void do_exit_shell(struct exit_callback *c, int signaled,
			  int core, int value)
{
  CAST(exit_shell, closure, c);
  struct server_session *session = closure->session;
  struct ssh_channel *channel = &session->super;
  
  CHECK_TYPE(server_session, session);

  if (! session->process->alive)
    {
      /* The process was killed by a the resource callback (most
       * likely because the connection died. Keep silent. */
      debug("do_exit_shell: Process already flagged as dead.\n");
      return;
    }
  
  /* No need to kill the process. */
  session->process->alive = 0;
  
  /* FIXME: Should we explicitly mark these files for closing? The
   * io-backend should notice EOF anyway. And the client should send
   * EOF when it receives news of the process's death, unless it
   * really wants to talk to any live children processes. */
#if 0
  close_fd(&session->in->super, 0);
  close_fd(session->out);
  close_fd(session->err);
#endif

  /* We close when we have both sent and received eof. */
  channel->flags |= CHANNEL_CLOSE_AT_EOF;
  
  if (!(channel->flags & CHANNEL_SENT_CLOSE))
    {
      A_WRITE(channel->write,
	      (signaled
	       ? format_exit_signal(channel, core, value)
	       : format_exit(channel, value)) );

      if ( (channel->flags & CHANNEL_SENT_EOF)
	   && (channel->flags & CHANNEL_RECEIVED_EOF))
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

/* GABA:
   (class
     (name shell_request)
     (super channel_request)
     (vars
       (backend object io_backend)
       (reap object reap)))
*/

/* Creates a one-way socket connection. Returns 1 on success, 0 on
 * failure. fds[0] is for reading, fds[1] for writing (like for the
 * pipe() system call). */
static int make_pipe(int *fds)
{
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      werror("socketpair() failed: %z\n", STRERROR(errno));
      return 0;
    }
  debug("Created socket pair. Using fd:s %i <-- %i\n", fds[0], fds[1]);

  if (SHUTDOWN(fds[0], SHUT_WR) < 0)
    {
      werror("shutdown(%i, SEND) failed: %z\n", fds[0], STRERROR(errno));
      goto fail;
    }
  if (SHUTDOWN(fds[1], SHUT_RD) < 0)
    {
      werror("shutdown(%i, REC) failed: %z\n", fds[0], STRERROR(errno));
    fail:
      {
	int saved_errno = errno;

	close(fds[0]);
	close(fds[1]);

	errno = saved_errno;
	return 0;
      }
    }
  
  return 1;
}

static int make_pipes(int *in, int *out, int *err)
{
  int saved_errno;
  
  if (make_pipe(in))
    {
      if (make_pipe(out))
	{
	  if (make_pipe(err))
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
static int make_pty(struct pty_info *pty, int *in, int *out, int *err)
{
  int saved_errno = 0;

  debug("make_pty... ");
  if (pty)
    debug("exists: \n"
	  "  alive = %i\n"
	  "  master = %i\n"
	  "  slave = %i\n"
	  "... ",
	  pty->super.alive, pty->master, pty->slave);
  debug("\n");
  
  if (pty && pty->super.alive)
    {
      debug("make_pty: Using allocated pty.\n");
      in[0] = pty->slave;
      in[1] = pty->master;

      /* Ownership of the fd:s passes on to some file objects. */
      pty->super.alive = 0;

      /* FIXME: It seems unnecessary to dup the fd:s here. But perhaps
       * having equal in and out fds may confuse the cleanup code, so
       * we leave it for now. */
      if ((out[0] = dup(pty->master)) != -1)
        {
          if ((out[1] = dup(pty->slave)) != -1) 
            {
#if BASH_WORKAROUND
	      /* Don't use a separate stderr channel; just dup the
	       * stdout pty to stderr. */
	      if ((err[1] = dup(pty->slave)) != -1)
                {
                  err[0] = -1;
                  return 1;
                } 
#else /* !BASH_WORKAROUND */
	      if (make_pipe(err))
		{
		  /* Success! */
		  return 1;
		}
#endif /* !BASH_WORKAROUND */
              saved_errno = errno;
	      
            }
	  else
	    saved_errno = errno;
	  close(out[0]);
	}
      else 
	saved_errno = errno;
      close(in[0]);
      close(in[1]);

      werror("make_pty: duping pty filedescriptors failed (errno = %i): %z\n",
	     errno, STRERROR(errno));
    }
  errno = saved_errno;
  return 0;
}
#else /* !WITH_PTY_SUPPORT */
static int make_pty(struct pty_info *pty UNUSED,
		    int *in UNUSED, int *out UNUSED, int *err UNUSED)
{ return 0; }
#endif /* !WITH_PTY_SUPPORT */

/* Strips any directory part of s. Both argument must be NUL
 * terminated. */
static const char *
lsh_basename(struct lsh_string *s)
{
  UINT8 *base;
  unsigned i;

  assert(NUL_TERMINATED(s));

  for (i = 0,  base = s->data; i < s->length; i++)
    {
      if (s->data[i] == '/')
	base = s->data + i + 1;
    };

  return base;
}
  
/* Returns -1 on failure, 0 for child and +1 for parent */
static int
spawn_process(struct server_session *session,
	      struct io_backend *backend,
	      struct reap *reap)
{
  int in[2];
  int out[2];
  int err[2];

  const char *tty = NULL;
  
  if (session->process)
    /* Already spawned a shell or command */
    return -1;
  
  /* {in|out|err}[0] is for reading,
   * {in|out|err}[1] for writing. */

  if (make_pty(session->pty, in, out, err))
    tty = lsh_basename(session->pty->tty_name);

  else if (!make_pipes(in, out, err))
    return -1;
  {
    pid_t child;
    
    if (USER_FORK(session->user, &child, tty))
      {
	if (child)
	  { /* Parent */
	    struct ssh_channel *channel = &session->super;
	    debug("Parent process\n");

	    session->process
	      = make_process_resource(child, format_cstring(tty), SIGHUP);
	    REAP(reap, child, make_exit_shell(session));
	  
	    /* Close the child's fd:s */
	    close(in[0]);
	    close(out[1]);
	    close(err[1]);

	    {
	      /* Exception handlers */
	      struct exception_handler *io_exception_handler
		= make_channel_io_exception_handler(channel,
						    "lshd: Child stdio: ",
						    &default_exception_handler,
						    HANDLER_CONTEXT);

	      /* Close callback for stderr and stdout */
	      struct close_callback *read_close_callback
		= make_channel_read_close_callback(channel);

	      session->in
		= io_write(make_lsh_fd(backend, in[1],
				       io_exception_handler),
			   SSH_MAX_PACKET, NULL);
	  
	      /* Flow control */
	      session->in->write_buffer->report = &session->super.super;

	      /* FIXME: Should we really use the same exception handler,
	       * which will close the channel on read errors, or is it
	       * better to just send EOF on read errors? */
	      session->out
		= io_read(make_lsh_fd(backend, out[0], io_exception_handler),
			  make_channel_read_data(channel),
			  read_close_callback);
	      session->err 
		= ( (err[0] != -1)
		    ? io_read(make_lsh_fd(backend, err[0], io_exception_handler),
			      make_channel_read_stderr(channel),
			      read_close_callback)
		    : NULL);
	    }
	
	    channel->receive = do_receive;
	    channel->send_adjust = do_send_adjust;
	    channel->eof = do_eof;
	  
	    /* Make sure that the process and it's stdio is
	     * cleaned up if the channel or connection dies. */
	    REMEMBER_RESOURCE
	      (channel->resources, session->process);
	    /* FIXME: How to do this properly if in and out may use the
	     * same fd? */
	    REMEMBER_RESOURCE
	      (channel->resources, &session->in->super);
	    REMEMBER_RESOURCE
	      (channel->resources, &session->out->super);
	    if (session->err)
	      REMEMBER_RESOURCE
		(channel->resources, &session->err->super);

	    return 1;
	  }
	else
	  { /* Child */
	    debug("spawn_process: Child process\n");
	    assert(getuid() == session->user->uid);
	    
	    if (!USER_CHDIR_HOME(session->user))
	      {
		werror("Could not change to home (or root) directory!\n");
		_exit(EXIT_FAILURE);
	      }
	    
#if WITH_PTY_SUPPORT
	    if (tty)
	      {
		debug("lshd: server.c: Setting controlling tty...\n");
		if (!tty_setctty(session->pty))
		  {
		    debug("lshd: server.c: "
			  "Setting controlling tty... Failed!\n");
		    werror("lshd: Can't set controlling tty for child!\n");
		    _exit(EXIT_FAILURE);
		  }
		else
		  debug("lshd: server.c: Setting controlling tty... Ok.\n");
	      }
#endif /* WITH_PTY_SUPPORT */
	  
	    /* Close all descriptors but those used for
	     * communicationg with parent. We rely on the
	     * close-on-exec flag for all fd:s handled by the
	     * backend. */
	    
	    if (dup2(in[0], STDIN_FILENO) < 0)
	      {
		werror("Can't dup stdin!\n");
		_exit(EXIT_FAILURE);
	      }
	    close(in[0]);
	    close(in[1]);
	    
	    if (dup2(out[1], STDOUT_FILENO) < 0)
	      {
		werror("Can't dup stdout!\n");
		_exit(EXIT_FAILURE);
	      }
	    close(out[0]);
	    close(out[1]);

	    if (!dup_error_stream())
	      {
		werror("server_session: Failed to dup old stderr. Bye.\n");
		set_error_ignore();
	      }

	    if (dup2(err[1], STDERR_FILENO) < 0)
	      {
		werror("Can't dup stderr!\n");
		_exit(EXIT_FAILURE);
	      }
	    close(err[0]);
	    close(err[1]);

	    return 0;
	  }
      }
    /* fork() failed */
    /* Close and return channel_failure */

    close(err[0]);
    close(err[1]);
    close(out[0]);
    close(out[1]);
    close(in[0]);
    close(in[1]);
  }
  return -1;
}

static struct exception shell_request_failed =
STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Shell request failed");

static void
do_spawn_shell(struct channel_request *c,
	       struct ssh_channel *channel,
	       struct ssh_connection *connection UNUSED,
	       UINT32 type UNUSED,
	       int want_reply UNUSED,
	       struct simple_buffer *args,
	       struct command_continuation *s,
	       struct exception_handler *e)
{
  CAST(shell_request, closure, c);
  CAST(server_session, session, channel);

  if (!parse_eod(args))
    {
      PROTOCOL_ERROR(e, "Invalid shell CHANNEL_REQUEST message.");
      return;
    }
    
  if (session->process)
    /* Already spawned a shell or command */
    goto fail;

  switch (spawn_process(session, closure->backend, closure->reap))
    {
    case 1: /* Parent */
      /* NOTE: The return value is not used. */
      COMMAND_RETURN(s, channel);
      channel_start_receive(channel, session->initial_window);
      return;
    case 0:
      { /* Child */
#define MAX_ENV 1
	/* No args, end the USER_EXEC method fills in argv[0]. */
	char *argv[] = { NULL, NULL };
	
	struct env_value env[MAX_ENV];
	int env_length = 0;
	
	debug("do_spawn_shell: Child process\n");
	assert(getuid() == session->user->uid);
	    	    
	if (session->term)
	  {
	    env[env_length].name ="TERM";
	    env[env_length].value = session->term;
	    env_length++;
	  }
	assert(env_length <= MAX_ENV);
#undef MAX_ENV

#if 1
	USER_EXEC(session->user, 1, argv, env_length, env);
	
	/* exec failed! */
	verbose("server_session: exec() failed (errno = %i): %z\n",
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
      /* fork() failed */

      break;
    default:
      fatal("Internal error!");
  }
 fail:
  EXCEPTION_RAISE(e, &shell_request_failed);
}

struct channel_request *
make_shell_handler(struct io_backend *backend,
		   struct reap *reap)
{
  NEW(shell_request, closure);

  closure->super.handler = do_spawn_shell;
  closure->backend = backend;
  closure->reap = reap;
  
  return &closure->super;
}

static struct exception exec_request_failed =
STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "Exec request failed");

static void
do_spawn_exec(struct channel_request *c,
	      struct ssh_channel *channel,
	      struct ssh_connection *connection UNUSED,
	      UINT32 type UNUSED,
	      int want_reply UNUSED,
	      struct simple_buffer *args,
	      struct command_continuation *s,
	      struct exception_handler *e)
{
  CAST(shell_request, closure, c);
  CAST(server_session, session, channel);

  UINT32 command_len;
  UINT8 *command;

  struct lsh_string *command_line;
  
  if (!(parse_string(args, &command_len, &command)
	&& parse_eod(args)))
    {
      PROTOCOL_ERROR(e, "Invalid exec CHANNEL_REQUEST message.");
      return;
    }
    
  if (session->process)
    /* Already spawned a shell or command */
    goto fail;

  command_line = make_cstring_l(command_len, command);
  if (!command_line)
    EXCEPTION_RAISE(e, &exec_request_failed);
  else
    switch (spawn_process(session, closure->backend, closure->reap))
    {
    case 1: /* Parent */
      lsh_string_free(command_line);

      /* NOTE: The return value is not used. */
      COMMAND_RETURN(s, channel);
      channel_start_receive(channel, session->initial_window);
      return;
    case 0:
      { /* Child */
#define MAX_ENV 1
	/* No args, end the USER_EXEC method fills in argv[0]. */
	char *argv[] = { NULL, "-c", command_line->data, NULL };
	
	struct env_value env[MAX_ENV];
	int env_length = 0;
	
	debug("do_spawn_shell: Child process\n");
	assert(getuid() == session->user->uid);
	    	    
	if (session->term)
	  {
	    env[env_length].name ="TERM";
	    env[env_length].value = session->term;
	    env_length++;
	  }
	assert(env_length <= MAX_ENV);
#undef MAX_ENV

	USER_EXEC(session->user, 0, argv, env_length, env);
	
	/* exec failed! */
	verbose("server_session: exec() failed (errno = %i): %z\n",
		errno, STRERROR(errno));
	_exit(EXIT_FAILURE);
      }
    case -1:
      /* fork() failed */
      lsh_string_free(command_line);

      break;
    default:
      fatal("Internal error!");
  }
 fail:
  EXCEPTION_RAISE(e, &shell_request_failed);
}

struct channel_request *
make_exec_handler(struct io_backend *backend,
		  struct reap *reap)
{
  NEW(shell_request, closure);

  closure->super.handler = do_spawn_exec;
  closure->backend = backend;
  closure->reap = reap;
  
  return &closure->super;
}

#if WITH_PTY_SUPPORT

static struct exception pty_request_failed =
STATIC_EXCEPTION(EXC_CHANNEL_REQUEST, "pty request failed");

/* pty_handler */
static void
do_alloc_pty(struct channel_request *c UNUSED,
	     struct ssh_channel *channel,
	     struct ssh_connection *connection UNUSED,
	     UINT32 type UNUSED,
	     int want_reply UNUSED,
	     struct simple_buffer *args,
	     struct command_continuation *s,
	     struct exception_handler *e)
{
  UINT32 width, height, width_p, height_p;
  UINT8 *mode;
  UINT32 mode_length;
  struct lsh_string *term = NULL;

  struct server_session *session = (struct server_session *) channel;

  verbose("Client requesting a tty...\n");
  
  /* The client may only request a tty once. */
  if (!session->pty &&
      (term = parse_string_copy(args)) &&
      parse_uint32(args, &width) &&
      parse_uint32(args, &height) &&
      parse_uint32(args, &width_p) &&
      parse_uint32(args, &height_p) &&
      parse_string(args, &mode_length, &mode) &&
      parse_eod(args))
    {
      struct pty_info *pty = make_pty_info();

      if (pty_allocate(pty, session->user->uid))
        {
          struct termios ios;

          if (tty_getattr(pty->slave, &ios))
            {
	      pty->super.alive = 1;
              session->pty = pty;

	      /* Don't set TERM if the value is empty. */
	      if (!term->length)
		{
		  lsh_string_free(term);
		  term = NULL;
		}
	      
              session->term = term;
              tty_decode_term_mode(&ios, mode_length, mode); 
	      
	      /* cfmakeraw(&ios); */
              if (tty_setattr(pty->slave, &ios) &&
                  tty_setwinsize(pty->slave,
				 width, height, width_p, height_p))
		{
		  REMEMBER_RESOURCE(channel->resources, &pty->super);

		  verbose(" granted.\n");
		  COMMAND_RETURN(s, NULL);

		  return;
		}
	      else
		/* Close fd:s and mark the pty-struct as dead */
		KILL_RESOURCE(&pty->super);
            }
        }
      KILL(pty);
    }

  verbose("Pty allocation failed.\n");
  lsh_string_free(term);

  EXCEPTION_RAISE(e, &pty_request_failed);
}

struct channel_request *make_pty_handler(void)
{
  NEW(channel_request, self);

  self->handler = do_alloc_pty;

  return self;
}
#endif /* WITH_PTY_SUPPORT */
