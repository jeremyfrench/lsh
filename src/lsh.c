/* lsh.c
 *
 * client main program
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

#include "algorithms.h"
#include "alist.h"
#include "atoms.h"
#include "channel.h"
#include "charset.h"
#include "client.h"
#include "client_keyexchange.h"
#include "client_pty.h"
#include "compress.h"
#include "connection_commands.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "io_commands.h"
#include "lookup_verifier.h"
#include "randomness.h"
#include "service.h"
#include "ssh.h"
#include "spki.h"
#include "tcpforward_commands.h"
#include "tty.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lsh_argp.h"

#include "lsh.c.x"

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel */
#define WINDOW_SIZE (SSH_MAX_PACKET << 3)


/* GABA:
   (class
     (name fake_host_db)
     (super lookup_verifier)
     (vars
       (algorithm object signature_algorithm)))
*/

static struct verifier *
do_host_lookup(struct lookup_verifier *c,
	       struct lsh_string *keyholder UNUSED,	       
	       struct lsh_string *key)
{
  CAST(fake_host_db, closure, c);

  return MAKE_VERIFIER(closure->algorithm, key->length, key->data);
}

static struct lookup_verifier *
make_fake_host_db(struct signature_algorithm *a)
{
  NEW(fake_host_db, res);

  res->super.lookup = do_host_lookup;
  res->algorithm = a;

  return &res->super;
}

/* GABA:
   (expr
     (name make_client_connect)
     (globals
       (progn "&progn_command.super.super")
       ;; FIXME: Use some function that also displays an error message
       ;; if connect() fails.
       (init_connection "&connection_service.super"))
       ;; (die_on_null "&command_die_on_null.super"))
     (params
       (connect object command)
       (handshake object command)
       (userauth_service object command)
       (login object command)
       ; (init_connection object command)
       (requests object object_list))
     (expr (lambda (port)
             ((progn requests) (init_connection
	         (login (userauth_service
	           (handshake (connect port)))))))))
*/

/* GABA:
   (expr
     (name make_start_session)
     (globals
       (progn "&progn_command.super.super"))
     (params
       (open_session object command)
       (requests object object_list))
     (expr (lambda (connection)
       ((progn requests) (open_session connection)))))
*/

/* Requests a shell, and connects the channel to our stdio. */
/* GABA:
   (expr
     (name start_shell)
     (super command)
     (globals
       (client_io "&client_io.super")
       (request_shell "&request_shell.super.super"))
     (expr
       (lambda (session)
          (client_io (request_shell session)))))
*/

static int parse_forward_arg(char *arg,
			     UINT32 *listen_port, struct address_info **target)
{
  char *first;
  char *second;
  char *end;
  long port;
  
  first = strchr(arg, ':');
  if (!first)
    return 0;

  second = strchr(first + 1, ':');
  if (!second || (second == first + 1))
    return 0;

  if (strchr(second + 1, ':'))
    return 0;

  port = strtol(arg, &end, 0);
  if ( (end == arg)  || (end != first)
       || (port < 0) || (port > 0xffff) )
    return 0;

  *listen_port = port;

  port = strtol(second + 1, &end, 0);
  if ( (end == second + 1) || (*end != '\0')
       || (port < 0) || (port > 0xffff) )
    return 0;

  *target = make_address_info(ssh_format("%ls", second - first - 1, first + 1), port);
  
  return 1;
}

/* FIXME: Resetting the tty should really be done by the corresponding
 * channel. */

#if WITH_PTY_SUPPORT
/* Global variable, because we use atexit() rather than on_exit() */
struct tty_state
{
  struct termios mode;
  int fd;
} old_tty;

static void reset_tty(void)
{
  tty_setattr(old_tty.fd, &old_tty.mode);
}

static int remember_tty(int fd)
{
  old_tty.fd = fd;
  return (tty_getattr(fd, &old_tty.mode)
	  && !atexit(reset_tty));
}
#endif /* WITH_PTY_SUPPORT */


/* Option parsing */

#define ARG_NOT 0x200

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },
  { "user", 'l', "User name", 0, "Login as this user.", 0 },
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { NULL, 0, NULL, 0, "Actions:", 0 },
  { "forward-local-port", 'L', "local-port:target-host:target-port", 0, "", 0 },
  { "forward-remote-port", 'R', "remote-port:target-host:target-port", 0, "", 0 },
  { "nop", 'N', NULL, 0, "No operation (suppresses the default action, "
    "which is to spawn a remote shell)", 0 },
  { NULL, 0, NULL, 0, "Modifiers that apply to port forwarding:", 0 },
  { "remote-peers", 'g', NULL, 0, "Allow remote access to forwarded ports", 0 },
  { "no-remote-peers", 'g' | ARG_NOT, NULL, 0, 
    "Disallow remote access to forwarded ports (default).", 0 },
#if WITH_PTY_SUPPORT
  { NULL, 0, NULL, 0, "Modifiers that apply to remote execution:", 0 },
  { "pty", 't', NULL, 0, "Request a remote pty (default).", 0 },
  { "no-pty", 't' | ARG_NOT, NULL, 0, "Don't request a remote pty.", 0 },
#endif /* WITH_PTY_SUPPORT */
  { NULL, 0, NULL, 0, "Universal not:", 0 },
  { "no", 'n', NULL, 0, "Inverts the effect of the next modifier", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

/* GABA:
   (class
     (name lsh_options)
     (super algorithms_options)
     (vars
       (backend object io_backend)
       (random object randomness)

       ; For i/o exceptions 
       (handler object exception_handler)

       (exit_code . "int *")
       
       (not . int)
       (port . "char *")
       (remote object address_info)

       (user . "char *")
       (identities struct object_queue)

       ; -1 means default behaviour
       (with_pty . int)

       (with_remote_peers . int)
       
       (start_shell . int)
       (remote_forward . int)
       (actions struct object_queue)))
*/

static struct lsh_options *
make_options(struct alist *algorithms, struct io_backend *backend,
	     struct randomness *random,
	     struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);

  init_algorithms_options(&self->super, algorithms);
  
  self->backend = backend;
  self->random = random;
  self->handler = handler;
  self->exit_code = exit_code;
  
  self->not = 0;
  self->remote = NULL;
  self->user = getenv("LOGNAME");
  self->port = "ssh";

  self->with_pty = -1;
  self->start_shell = 1;
  self->with_remote_peers = 0;
  object_queue_init(&self->actions);
  object_queue_init(&self->identities);
  
  return self;
}

static const struct argp_child
main_argp_children[] =
{
  { &algorithms_argp, 0, "", 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      state->child_inputs[1] = NULL;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!state->arg_num)
	{
	  self->remote = make_address_info_c(arg, self->port);
	  
	  if (!self->remote)
	    argp_error(state, "Invalid port or service '%s'.", self->port);

	  break;
	}
      else
	/* Let the next case parse it.  */
	return ARGP_ERR_UNKNOWN;

      break;
    case ARGP_KEY_ARGS:
      argp_error(state, "Providing a remote command on the command is not supported yet.");
      break;

    case ARGP_KEY_END:
      if (!self->user)
	{
	  argp_error(state, "No user name given. Use the -l option, or set LOGNAME in the environment.");
	  break;
	}

#if WITH_TCP_FORWARD
      if (self->remote_forward)
	object_queue_add_tail
	  (&self->actions,
	   &make_install_fix_channel_open_handler
	   (ATOM_FORWARDED_TCPIP, &channel_open_forwarded_tcpip)->super);
#endif /* WITH_TCP_FORWARD */
      
      /* Add shell action */
      if (self->start_shell)
	{
	  int in;
	  int out;
	  int err;
	  int tty;

	  struct command *get_pty = NULL;
	  
	  struct object_list *session_requests;
      
#if WITH_PTY_SUPPORT
	  if (self->with_pty)
	    {
	      tty = open("/dev/tty", O_RDWR);
      
	      if (tty < 0)
		{
		  werror("lsh: Failed to open tty (errno = %i): %z\n",
			 errno, STRERROR(errno));
		}
	      else
		{
		  /* FIXME: If we are successful, the tty is probably never closed. */
		  if (! (remember_tty(tty)
			 && (get_pty = make_pty_request(tty))))
		    {
		      werror("lsh: Can't use tty (probably getettr or atexit() failed.\n");
		      close(tty);
		      tty = -1;
		    }
		}
	    }
	  /* FIXME: We need a non-varargs constructor for lists. */
	  if (get_pty)
	    session_requests = make_object_list(2, get_pty, start_shell(), -1);
	  else
#endif /* WITH_PTY_SUPPORT */
	    session_requests = make_object_list(1, start_shell(), -1);
	  
	  in = STDIN_FILENO;
	  out = STDOUT_FILENO;
	  
	  if ( (err = dup(STDERR_FILENO)) < 0)
	    {
	      argp_failure(state, EXIT_FAILURE, errno, "Can't dup stderr: %s", STRERROR(errno));
	      fatal("Can't happen.\n");
	    }

	  set_error_stream(STDERR_FILENO, 1);
	  
	  /* Exit code if no session is established */
	  *self->exit_code = 17;
	  
	  object_queue_add_tail
	    (&self->actions,
	     make_start_session
	     (make_open_session_command(make_client_session
					(io_read(make_io_fd(self->backend, in, self->handler),
						 NULL, NULL),
					 io_write(make_io_fd(self->backend, out, self->handler),
						  BLOCK_SIZE, NULL),
					 io_write(make_io_fd(self->backend, err, self->handler),
						  BLOCK_SIZE, NULL),
					 WINDOW_SIZE,
					 self->exit_code)),
	      session_requests));
	}
	  
      if (object_queue_is_empty(&self->actions))
	{
	  argp_error(state, "No actions given.");
	  break;
	}

      if (object_queue_is_empty(&self->identities))
	{
	  char *home = getenv("HOME");
	  if (home)
	    {
	      struct lsh_string *idfile = 
		ssh_format("%lz/.lsh/identity%c", home, 0);
	      struct keypair *id;
	      if ((id = read_spki_key_file(idfile->data, self->random, self->handler)))
		{
		  verbose("Adding identity %S\n", idfile);
		  object_queue_add_tail(&self->identities, &id->super);
		}
	      lsh_string_free(idfile);
	    }
	}
      
      break;
      
    case 'p':
      self->port = arg;
      break;
    case 'l':
      self->user = arg;
      break;
    case 'i':
      {
	struct keypair *id;
	if ((id = read_spki_key_file(arg, self->random, self->handler)))
	  {
	    verbose("Adding identity %s\n", arg);
	    object_queue_add_tail(&self->identities, &id->super);
	  }
	break;
      }
    case 'L':
      {
	UINT32 listen_port;
	struct address_info *target;

	if (!parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	object_queue_add_tail(&self->actions,
			      &make_forward_local_port
			      (self->backend,
			       make_address_info((self->with_remote_peers
						  ? NULL
						  : ssh_format("%lz", "127.0.0.1")),
						 listen_port),
			       target)->super);
	break;
      }      

    case 'R':
      {
	UINT32 listen_port;
	struct address_info *target;

	if (!parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	object_queue_add_tail(&self->actions,
			      &make_forward_remote_port
			      (self->backend,
			       make_address_info((self->with_remote_peers
						  /* FIXME: Is NULL an ok value? */
						  ? ssh_format("%lz", "0.0.0.0")
						  : ssh_format("%lz", "127.0.0.1")),
						 listen_port),
			       target)->super);
	self->remote_forward = 1;
	break;
      }      

    case 'N':
      self->start_shell = 0;
      break;
    case 'g':
      if (self->not)
	{
	  self->not = 0;

	case 'g' | ARG_NOT:
	  self->with_remote_peers = 0;
	  break;
	}
      
      self->with_remote_peers = 1;
      break;
#if WITH_PTY_SUPPORT
    case 't':
      if (self->not)
	{
	  self->not = 0;

	case 't' | ARG_NOT:
	  self->with_pty = 0;
	  break;
	}
      self->with_pty = 1;
      break;
#endif /* WITH_PTY_SUPPORT */

    case 'n':
      self->not = !self->not;
      break;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  ( "host\n"
    "host command ..."), 
  ( "Connects to a remote machine\v"
    "Connects to the remote machine, and then performs one or more actions, "
    "i.e. command execution, various forwarding services. The default "
    "action is to start a remote interactive shell or execute a given "
    "command on the remote machine." ),
  main_argp_children,
  NULL, NULL
};

/* GABA:
   (class
     (name lsh_default_handler)
     (super exception_handler)
     (vars
       (status . "int *")))
*/

static void
do_lsh_default_handler(struct exception_handler *s,
		       const struct exception *e)
{
  CAST(lsh_default_handler, self, s);

  if (e->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, exc, e);

      switch(e->type)
	{
#if 0
	case EXC_IO_EOF:
	  close_fd_nicely(exc->fd, 0);
	  break;
#endif
	default:
	  *self->status = EXIT_FAILURE;
	  EXCEPTION_RAISE(self->super.parent, e);
	  return;
	}
      werror("lsh: %z, (errno = %i)\n", e->msg, exc->error);
    }
  else
    switch(e->type)
      {
      case EXC_RESOLVE:
      case EXC_AUTH:
      case EXC_SERVICE:
	werror("lsh: %z\n", e->msg);
	*self->status = EXIT_FAILURE;
	break;
      default:
	*self->status = EXIT_FAILURE;
	EXCEPTION_RAISE(self->super.parent, e);
      }
}

static struct exception_handler *
make_lsh_default_handler(int *status, struct exception_handler *parent,
			 const char *context)
{
  NEW(lsh_default_handler, self);
  self->super.parent = parent;
  self->super.raise = do_lsh_default_handler;
  self->super.context = context;
  
  self->status = status;

  return &self->super;
}

int main(int argc, char **argv)
{
  struct lsh_options *options;
  
  int lsh_exit_code = 0;

  struct randomness *r;
  struct diffie_hellman_method *dh;
  struct keyexchange_algorithm *kex;
  struct alist *algorithms;
  struct make_kexinit *make_kexinit;
  struct alist *lookup_table; /* Alist of signature-algorithm -> lookup_verifier */

  /* int in, out, err; */

  /* FIXME: A single exception handler everywhere seems a little to
   * crude. */
  struct exception_handler *handler
    = make_lsh_default_handler(&lsh_exit_code, &default_exception_handler,
			       HANDLER_CONTEXT);

  /* FIXME: Why not allocate backend statically? */
  NEW(io_backend, backend);
  init_backend(backend);
  
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  r = make_reasonably_random();
  dh = make_dh1(r);

  /* No randomness is needed for verifying signatures */
  lookup_table = make_alist(1
			    , ATOM_SSH_DSS, make_fake_host_db(make_dsa_algorithm(NULL)),
			    -1); 

  kex = make_dh_client(dh, lookup_table);
  algorithms = many_algorithms(2, 
			       ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, kex,
			       ATOM_SSH_DSS, make_dsa_algorithm(r),
			       -1);


  options = make_options(algorithms, backend, r, handler, &lsh_exit_code);

  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);
  
  make_kexinit
    = make_simple_kexinit(r,
			  make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
					-1),
			  make_int_list(1, ATOM_SSH_DSS, -1),
			  options->super.crypto_algorithms,
			  options->super.mac_algorithms,
			  options->super.compression_algorithms,
			  make_int_list(0, -1));
  {
    struct lsh_object *o =
      make_client_connect(make_simple_connect(backend, NULL),
			  make_handshake_command(CONNECTION_CLIENT,
						 "lsh - a free ssh",
						 SSH_MAX_PACKET,
						 r,
						 algorithms,
						 make_kexinit,
						 NULL),
			  make_request_service(ATOM_SSH_USERAUTH),
			  make_client_userauth(
			    ssh_format("%lz", options->user),
			    ATOM_SSH_CONNECTION,
			    /* FIXME: Move this logic into the option parser. */
			    (object_queue_is_empty(&options->identities)
			     ? make_object_list(1, make_client_password_auth(), 
						-1)
			     : make_object_list(2, 
						make_client_publickey_auth(queue_to_list(&options->identities)),
						make_client_password_auth(), 
						-1))),
			  queue_to_list(&options->actions));
    
    CAST_SUBTYPE(command, client_connect, o);

    COMMAND_CALL(client_connect, options->remote, &discard_continuation,
		 handler);
	
  } 

  /* We can free the options and action queue now */
  KILL(options);

  io_run(backend);
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  
  return lsh_exit_code;
}
