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

#include "format.h"
#include "server_password.h"
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
/* #include <pwd.h> */

#if HAVE_UTMP_H
#include <utmp.h>
#endif

#if HAVE_UTMPX_H
#include <utmpx.h>
#endif

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
		 errno, strerror(errno));
	}
    }
}
          
struct resource *make_process_resource(pid_t pid, int signal)
{
  NEW(process_resource, self);
  self->super.alive = 1;

  self->pid = pid;
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
       (user object unix_user)

       ; Non-zero if a shell or command has been started. 
       ;; (running simple int)

       ; Resource to kill when the channel is closed. 
       (process object resource)

       ; pty
       (pty object pty_info)
       ; value of the TERM environment variable
       (term string)

       ; Child process's stdio 
       (in object io_fd)
       (out object io_fd)
       ;; err may be NULL, if there's no separate stderr channel.
       ;; This happens if we use a pty, and the bash workaround
       (err object io_fd)))
*/

/* Receive channel data */
static int do_receive(struct ssh_channel *c,
		      int type, struct lsh_string *data)
{
  CAST(server_session, closure, c);

  /* FIXME: Examine the size of the write buffer, to decide if the
   * receive window should be adjusted. */
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
  CAST(server_session, session, c);

  assert(session->out->super.read);
  assert(session->out->handler);

  session->out->super.want_read = 1;

  if (session->err)
    {
      assert(session->err->super.read);
      assert(session->err->handler);
  
      session->err->super.want_read = 1;
    }
  return LSH_OK | LSH_GOON;
}

static int do_eof(struct ssh_channel *channel)
{
  CAST(server_session, session, channel);

  write_buffer_close(session->in->buffer);

  if ( (channel->flags & CHANNEL_SENT_EOF)
       && (channel->flags & CHANNEL_CLOSE_AT_EOF))
    return channel_close(channel);
  else
    return LSH_OK | LSH_GOON;
}

static int do_close(struct ssh_channel *c)
{
  CAST(server_session, session, c);

  if (session->process)
    KILL_RESOURCE(session->process);

  return LSH_OK;
}

struct ssh_channel *make_server_session(struct unix_user *user,
					UINT32 max_window,
					struct alist *request_types)
{
  NEW(server_session, self);

  init_channel(&self->super);

  self->super.max_window = max_window;
  /* We don't want to receive any data before we have forked some
   * process to receive it. */
  self->super.rec_window_size = 0;

  /* FIXME: Make maximum packet size configurable. */
  self->super.rec_max_packet = SSH_MAX_PACKET;

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
       (user object unix_user)
       (session_requests object alist)))
*/

#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

static int do_open_session(struct channel_open *c,
                           struct ssh_connection *connection UNUSED,
                           struct simple_buffer *args,
                           struct channel_open_callback *response)
{
  CAST(open_session, closure, c);
  struct ssh_channel *session = NULL;
  UINT32 error;
  char *error_msg;

  debug("server.c: do_open_session()\n");

  if (parse_eod(args))
    {
      session = make_server_session(closure->user,
				    WINDOW_SIZE, closure->session_requests);
      error = 0;
      error_msg = NULL;
    }
  else
    {
      error = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
      error_msg = "trailing garbage in open message";
    }
   return CHANNEL_OPEN_CALLBACK(response, session, error, error_msg, NULL); 
}

struct channel_open *make_open_session(struct unix_user *user,
				       struct alist *session_requests)
{
  NEW(open_session, closure);

  closure->super.handler = do_open_session;
  closure->user = user;
  closure->session_requests = session_requests;
  
  return &closure->super;
}

/* A command taking two arguments: unix_user, connection */
/* GABA:
   (class
     (name server_connection_service)
     (super command)
     (vars
       (global_requests object alist)

       ; Requests specific to session channels 
       (session_requests object alist)

       ; io_backend, needed for direct_tcpip
       (backend object io_backend) ))
*/

/* Start an authenticated ssh-connection service */
static int do_login(struct command *s,
		    struct lsh_object *x,
		    struct command_continuation *c)
{
  CAST(server_connection_service, closure, s);
  CAST(unix_user, user, x);
  
  debug("server.c: do_login()\n");
  
  return COMMAND_RETURN
    (c, make_connection_service
     (closure->global_requests,
      /* FIXME: It would be better to take one more alists as
       * arguments, and cons the ATOM_SESSION service at the head of
       * it. But that won't work as long as an alist doesn't consists
       * of independent cons-objects. */
      make_alist(2, 
		 ATOM_SESSION, make_open_session(user,
						 closure->session_requests),
		 ATOM_DIRECT_TCPIP, make_open_direct_tcpip(closure->backend), 
		 -1)));
}

struct command *
make_server_connection_service(struct alist *global_requests,
			       struct alist *session_requests,
			       struct io_backend *backend)
{
  NEW(server_connection_service, closure);

  closure->super.call = do_login;
  closure->global_requests = global_requests;
  closure->session_requests = session_requests;
  closure->backend = backend;

  return &closure->super;
}

struct lsh_string *format_exit_signal(struct ssh_channel *channel,
				      int core, int signal)
{
  struct lsh_string *msg = ssh_format("Process killed by %lz.\n",
				      strsignal(signal));
  
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
      int res = A_WRITE(channel->write,
		    signaled
		    ? format_exit_signal(channel, core, value)
		    : format_exit(channel, value));

      if (!LSH_CLOSEDP(res)
	  && (channel->flags & CHANNEL_SENT_EOF)
	  && (channel->flags & CHANNEL_RECEIVED_EOF))
	{
	  /* We have sent EOF already, so initiate close */
	  res |= channel_close(channel);
	}

      /* FIXME: Can we do anything better with the return code than
       * ignore it? */

      (void) res;
      return;
    }
}

static struct exit_callback *make_exit_shell(struct server_session *session)
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
      werror("socketpair() failed: %z\n", strerror(errno));
      return 0;
    }
  debug("Created socket pair. Using fd:s %i <-- %i\n", fds[0], fds[1]);

  if (SHUTDOWN(fds[0], SHUT_WR) < 0)
    {
      werror("shutdown(%i, SEND) failed: %z\n", fds[0], strerror(errno));
      goto fail;
    }
  if (SHUTDOWN(fds[1], SHUT_RD) < 0)
    {
      werror("shutdown(%i, REC) failed: %z\n", fds[0], strerror(errno));
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

static char *make_env_pair(const char *name, struct lsh_string *value)
{
  return ssh_format("%lz=%lS%c", name, value, 0)->data;
}

static char *make_env_pair_c(const char *name, char *value)
{
  return ssh_format("%lz=%lz%c", name, value, 0)->data;
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
	     errno, strerror(errno));
    }
  errno = saved_errno;
  return 0;
}
#else /* !WITH_PTY_SUPPORT */
static int make_pty(struct pty_info *pty UNUSED,
		    int *in UNUSED, int *out UNUSED, int *err UNUSED)
{ return 0; }
#endif /* !WITH_PTY_SUPPORT */

#define USE_LOGIN_DASH_CONVENTION 1

static int do_spawn_shell(struct channel_request *c,
			  struct ssh_channel *channel,
			  struct ssh_connection *connection,
			  int want_reply,
			  struct simple_buffer *args)
{
  CAST(shell_request, closure, c);
  struct server_session *session = (struct server_session *) channel;

  int in[2];
  int out[2];
  int err[2];

  int using_pty = 0;
  
  CHECK_TYPE(server_session, session);

  if (!parse_eod(args))
    return LSH_FAIL | LSH_DIE;

  if (session->process)
    /* Already spawned a shell or command */
    goto fail;
  
  /* {in|out|err}[0] is for reading,
   * {in|out|err}[1] for writing. */

  if (make_pty(session->pty, in, out, err))
    using_pty = 1;

  else if (!make_pipes(in, out, err))
    goto fail;
  {
    pid_t child;
      
    switch(child = fork())
      {
      case -1:
	werror("fork() failed: %z\n", strerror(errno));
	/* Close and return channel_failure */
	break; 
      case 0:
	{ /* Child */
	  char *shell;
#define MAX_ENV 8
	  char *env[MAX_ENV];
	  char *tz = getenv("TZ");
	  int i = 0;

	  int old_stderr;
	    
	  debug("do_spawn_shell: Child process\n");
	  if (!session->user->shell)
	    {
	      werror("No login shell!\n");
	      exit(EXIT_FAILURE);
	    }

	  shell = session->user->shell->data;
	    
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

	  debug("Child: Setting up environment.\n");
	    
	  env[i++] = make_env_pair("LOGNAME", session->user->name);
	  env[i++] = make_env_pair("USER", session->user->name);
	  env[i++] = make_env_pair("SHELL", session->user->shell);
	  if (session->term)
	    env[i++] = make_env_pair("TERM", session->term);
	  if (session->user->home)
	    env[i++] = make_env_pair("HOME", session->user->home);
	  if (tz)
	    env[i++] = make_env_pair_c("TZ", tz);

	  /* FIXME: The value of $PATH should not be hard-coded */
	  env[i++] = "PATH=/bin:/usr/bin";
	  env[i++] = NULL;
	    
	  assert(i <= MAX_ENV);
#undef MAX_ENV

	  debug("Child: Environment:\n");
	  for (i=0; env[i]; i++)
	    debug("Child:   '%z'\n", env[i]);

	  /* We do this before closing fd:s, because the sysv version
	   * of tty_setctty depends on the master pty fd still open.
	   * It would be cleaner if we could pass the slave fd only
	   * (i.e. STDIN_FILENO) to tty_setctty(). */
#if WITH_PTY_SUPPORT
	  if (using_pty)
	    {
	      debug("lshd: server.c: Setting controlling tty...\n");
	      if (!tty_setctty(session->pty))
		{
		  debug("lshd: server.c: "
			"Setting controlling tty... Failed!\n");
		  werror("lshd: Can't set controlling tty for child!\n");
		  exit(EXIT_FAILURE);
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
	      exit(EXIT_FAILURE);
	    }
	  close(in[0]);
	  close(in[1]);
	    
	  if (dup2(out[1], STDOUT_FILENO) < 0)
	    {
	      werror("Can't dup stdout!\n");
	      exit(EXIT_FAILURE);
	    }
	  close(out[0]);
	  close(out[1]);

	  if ((old_stderr = dup(STDERR_FILENO)) < 0)
	    {
	      werror("Couldn't save old file_no.\n");
	      set_error_ignore();
	    }
	  else
	    {
	      io_set_close_on_exec(old_stderr);
	      set_error_stream(old_stderr, 1);
	    }
	  /* debug("Child: Duping stderr (bye).\n"); */
	  
	  if (dup2(err[1], STDERR_FILENO) < 0)
	    {
	      werror("Can't dup stderr!\n");
	      exit(EXIT_FAILURE);
	    }
	  close(err[0]);
	  close(err[1]);
	  
#if 1
#if USE_LOGIN_DASH_CONVENTION
	  {
	    char *argv0 = alloca(session->user->shell->length + 2);
	    char *p;

	    debug("lshd: server.c: fixing up name of shell...\n");
	    /* Make sure that the shell's name begins with a -. */
	    p = strrchr (shell, '/');
	    if (!p)
	      p = shell;
	    else
	      p ++;
	      
	    argv0[0] = '-';
	    strncpy (argv0 + 1, p, session->user->shell->length);
	    debug("lshd: server.c: fixing up name of shell... done.\n");
#if 0
	    /* Not needed; shell and p should be NUL-terminated properly. */
	    argv0[sizeof (argv0) - 1] = '\0';
#endif	      
	    execle(shell, argv0, NULL, env);
	  }
#else /* !USE_LOGIN_DASH_CONVENTION */
	  execle(shell, shell, NULL, env);
#endif /* !USE_LOGIN_DASH_CONVENTION */
#else
#define GREETING "Hello world!\n"
	  if (write(STDOUT_FILENO, GREETING, strlen(GREETING)) < 0)
	    _exit(errno);
	  kill(getuid(), SIGSTOP);
	  if (write(STDOUT_FILENO, shell, strlen(shell)) < 0)
	    _exit(125);
	  _exit(126);
#undef GREETING
#endif
	  /* exec failed! */
	  {
	    int exec_errno = errno;

	    if (dup2(old_stderr, STDERR_FILENO) < 0)
	      {
		/* This is really bad... We can't restore stderr
		 * to report our problems. */
		char msg[] = "child: execle() failed!\n";
		write(old_stderr, msg, sizeof(msg));
	      }
	    else
	      debug("Child: execle() failed (errno = %i): %z\n",
		    exec_errno, strerror(exec_errno));
	    _exit(EXIT_FAILURE);
	  }
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
	  = io_write(make_io_fd(closure->backend, in[1]),
		     SSH_MAX_PACKET,
		     /* FIXME: Use a proper close callback */
		     make_channel_close(channel));
	session->out
	  = io_read(make_io_fd(closure->backend, out[0]),
		    make_channel_read_data(channel),
		    NULL);
	session->err 
	  = ( (err[0] != -1)
	      ? io_read(make_io_fd(closure->backend, err[0]),
			make_channel_read_stderr(channel),
			NULL)
	      : NULL);
	
	channel->receive = do_receive;
	channel->send = do_send;
	channel->eof = do_eof;
	  
	session->process
	  = make_process_resource(child, SIGHUP);

	/* Make sure that the process and it's stdio is
	 * cleaned up if the connection dies. */
	REMEMBER_RESOURCE
	  (connection->resources, session->process);
	/* FIXME: How to do this properly if in and out may use the
	 * same fd? */
	REMEMBER_RESOURCE
	  (connection->resources, &session->in->super.super);
	REMEMBER_RESOURCE
	  (connection->resources, &session->out->super.super);
	if (session->err)
	  REMEMBER_RESOURCE
	    (connection->resources, &session->err->super.super);

	return (want_reply
		? A_WRITE(channel->write,
			  format_channel_success(channel
						 ->channel_number))
		: 0) | LSH_CHANNEL_READY_REC;
      }
    close(err[0]);
    close(err[1]);
    close(out[0]);
    close(out[1]);
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
  NEW(shell_request, closure);

  closure->super.handler = do_spawn_shell;
  closure->backend = backend;
  closure->reap = reap;
  
  return &closure->super;
}

#if WITH_PTY_SUPPORT
/* pty_handler */
static int do_alloc_pty(struct channel_request *c UNUSED,
                        struct ssh_channel *channel,
                        struct ssh_connection *connection UNUSED,
                        int want_reply,
                        struct simple_buffer *args)
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
		  term = 0;
		}
	      
              session->term = term;
              tty_decode_term_mode(&ios, mode_length, mode); 
	      
	      /* cfmakeraw(&ios); */
              if (tty_setattr(pty->slave, &ios) &&
                  tty_setwinsize(pty->slave,
				 width, height, width_p, height_p))
		{
		  REMEMBER_RESOURCE(connection->resources, &pty->super);

		  verbose(" granted.\n");
		  return want_reply
		    ? A_WRITE(channel->write,
			      format_channel_success(channel->channel_number))
		    : LSH_OK;
		}
	      else
		/* Close fd:s and mark the pty-struct as dead */
		KILL_RESOURCE(&pty->super);
            }
        }
      KILL(pty);
    }

  verbose(" failed.\n");
  lsh_string_free(term);
  return want_reply
    ? A_WRITE(channel->write, format_channel_failure(channel->channel_number))
    : LSH_OK | LSH_GOON;
}

struct channel_request *make_pty_handler(void)
{
  NEW(channel_request, self);

  self->handler = do_alloc_pty;

  return self;
}
#endif /* WITH_PTY_SUPPORT */
