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
#include "client_userauth.h"
#include "compress.h"
#include "connection_commands.h"
#include "crypto.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "io_commands.h"
#include "lookup_verifier.h"
#include "randomness.h"
#include "service.h"
#include "sexp.h"
#include "spki_commands.h"
#include "ssh.h"
#include "tcpforward_commands.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
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

/* Forward declarations */
struct command_simple options2remote;
#define OPTIONS2REMOTE (&options2remote.super.super)

struct command_simple lsh_verifier_command;
#define OPTIONS2VERIFIER (&lsh_verifier_command.super.super)

struct command_simple lsh_login_command;
#define LSH_LOGIN (&lsh_login_command.super.super)

static struct command options2known_hosts;
#define OPTIONS2KNOWN_HOSTS (&options2known_hosts.super)

static struct command options2identities;
#define OPTIONS2IDENTITIES (&options2identities.super)
		    
#include "lsh.c.x"

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel */
#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

/* GABA:
   (class
     (name lsh_options)
     (super algorithms_options)
     (vars
       (backend object io_backend)

       (signature_algorithms object alist)
       (home . "const char *")
       
       ; For i/o exceptions 
       (handler object exception_handler)

       (exit_code . "int *")
       
       (not . int)
       (port . "char *")
       (remote object address_info)

       (user . "char *")
       (identity . "char *")
       (publickey . int)

       (sloppy . int)
       (capture . "const char *")
       (capture_file object abstract_write)

       (known_hosts . "const char *")
       
       ; -1 means default behaviour
       (with_pty . int)

       (with_remote_peers . int)
       
       (start_shell . int)
       (remote_forward . int)
       (actions struct object_queue)))
*/


static struct lsh_options *
make_options(struct alist *algorithms,
	     struct io_backend *backend,
	     struct randomness *random,
	     struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);

  init_algorithms_options(&self->super, algorithms);
  
  self->backend = backend;

  self->home = getenv("HOME");
  
  self->signature_algorithms
    = make_alist(1,
		 ATOM_DSA, make_dsa_algorithm(random), -1);
  
  self->handler = handler;
  self->exit_code = exit_code;
  
  self->not = 0;
  self->remote = NULL;
  self->user = getenv("LOGNAME");
  self->port = "ssh";

  self->sloppy = 0;
  self->capture = NULL;
  self->capture_file = NULL;

  self->known_hosts = NULL;
  /* self->known_hosts_file = NULL; */
  
  self->with_pty = -1;
  self->start_shell = 1;
  self->with_remote_peers = 0;
  object_queue_init(&self->actions);

  self->publickey = 1;
  
  return self;
}


/* Host to connect to */
COMMAND_SIMPLE(options2remote)
{
  CAST(lsh_options, options, a);
  return &options->remote->super;
}

/* Open hostkey database. By default, "~/.lsh/known_hosts". */

static void
do_options2known_hosts(struct command *ignored UNUSED,
		       struct lsh_object *a,
		       struct command_continuation *c,
		       struct exception_handler *e)
{
  CAST(lsh_options, options, a);
  
  struct lsh_string *tmp = NULL;
  const char *s = NULL;
  struct io_fd *f;
  
  if (options->known_hosts)
    s = options->known_hosts;
  else 
    {
      tmp = ssh_format("%lz/.lsh/known_hosts%c", options->home, 0);
      s = tmp->data;
    }
  
  f = io_read_file(options->backend, s, e);

  if (!f)
    {
      werror("Failed to open '%z' (errno = %i): %z.\n",
	     s, errno, STRERROR(errno));
      COMMAND_RETURN(c, make_spki_context(options->signature_algorithms));
    }
  else
    {
      CAST_SUBTYPE(command, read,
		   make_spki_read_acls(options->signature_algorithms));
      COMMAND_CALL(read, f, c, e);
    }
  lsh_string_free(tmp);
}

static struct command options2known_hosts =
STATIC_COMMAND(do_options2known_hosts);

/* Read user's private keys. By default, "~/.lsh/identity". */
static void
do_options2identities(struct command *ignored UNUSED,
		      struct lsh_object *a,
		      struct command_continuation *c,
		      struct exception_handler *e)
{
  CAST(lsh_options, options, a);
  
  struct lsh_string *tmp = NULL;
  const char *s = NULL;
  struct io_fd *f = 0;

  if (options->publickey)
    {
      COMMAND_RETURN(c, make_object_list(0, -1));
      return;
    }
  if (options->identity)
    s = options->identity;
  else 
    {
      tmp = ssh_format("%lz/.lsh/identity%c", options->home, 0);
      s = tmp->data;
    }
  
  f = io_read_file(options->backend, s, e);
  
  if (!f)
    {
      werror("Failed to open '%z' (errno = %i): %z.\n",
	     s, errno, STRERROR(errno));
      COMMAND_RETURN(c, make_object_list(0, -1));
    }
  else
    COMMAND_CALL(&spki_read_userkeys_command.super, f, c, e);
  
  lsh_string_free(tmp);
}

static struct command options2identities =
STATIC_COMMAND(do_options2identities);

/* GABA:
   (class
     (name options_command)
     (super command)
     (vars
       (options object lsh_options)))
*/

static struct command *
make_options_command(struct lsh_options *options,
		     void (*call)(struct command *s,
				  struct lsh_object *a,
				  struct command_continuation *c,
				  struct exception_handler *e))
{
  NEW(options_command, self);
  self->super.call = call;
  self->options = options;

  return &self->super;
}

/* Maps a host key to a (trusted) verifier object.
 *
 * NOTE: Handles only ssh-dss keys. */

/* GABA:
   (class
     (name lsh_host_db)
     (super lookup_verifier)
     (vars
       (db object spki_context)
       (access object sexp)
       (host object address_info)
       ; Allow unauthorized keys
       (sloppy . int)
       ; If non-null, append an ACL for the received key to this file.
       (file object abstract_write)
       (hash object hash_algorithm) ; For fingerprinting
       ;; (algorithm object signature_algorithm)
       ))
*/

static struct verifier *
do_lsh_lookup(struct lookup_verifier *c,
	      int method,
	      struct lsh_string *keyholder UNUSED,
	      struct lsh_string *key)
{
  CAST(lsh_host_db, self, c);
  struct spki_subject *subject;

  switch (method)
    {
    case ATOM_SSH_DSS:
      {
	struct dsa_verifier *v = make_ssh_dss_verifier(key->length, key->data);
	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-dss key.\n");
	    return NULL;
	  }
	subject = SPKI_LOOKUP(self->db,
			      dsa_to_spki_public_key(&v->public),
			      &v->super);
	assert(subject);
	assert(subject->verifier);
	break;
      }
    case ATOM_SPKI:
      {
	struct sexp *e = string_to_sexp(key, 0);
	if (!e)
	  {
	    werror("do_lsh_lookup: Invalid spki s-expression.\n");
	    return NULL;
	  }
	  
	subject = SPKI_LOOKUP(self->db, e, NULL);
	if (!subject)
	  {
	    werror("do_lsh_lookup: Invalid spki key.\n");
	    return NULL;
	  }
	if (!subject->verifier)
	  {
	    werror("do_lsh_lookup: Valid SPKI subject, but no key available.\n");
	    return NULL;
	  }
	break;
      }
    default:
      werror("do_lsh_lookup: Unknown key type. Should not happen!\n");
      return NULL;
    }

  assert(subject->key);
  
  /* Check authorization */

  if (SPKI_AUTHORIZE(self->db, subject, self->access))
    {
      verbose("SPKI authorization successful!");
    }
  else
    {
      verbose("SPKI authorization failed.\n");
      if (!self->sloppy)
	{
	  werror("lsh: Server's hostkey is not trusted. Disconnecting.\n");
	  return NULL;
	}
      
      /* Ok, let's see if we want to use this untrusted key. */
      if (!quiet_flag)
	{
	  /* Display fingerprint */
	  struct lsh_string *fingerprint
	    = hash_string(self->hash,
			  sexp_format(subject->key, SEXP_CANONICAL, 0),
			  1);
			  
	  if (!yes_or_no(ssh_format("Received unauthenticated key for host %lS\n"
				    "Fingerprint: %lfxS\n"
				    "Do you trust this key? (y/n) ",
				    self->host->ip, fingerprint), 0, 1))
	    return NULL;
	}
      
      /* Write an ACL to disk. */
      if (self->file)
	{
	  A_WRITE(self->file, ssh_format("\n; ACL for host %lS\n", self->host->ip));
	  A_WRITE(self->file,
		  sexp_format(sexp_l(2, sexp_a(ATOM_ACL),
				     sexp_l(3, sexp_a(ATOM_ENTRY),
					    subject->key,
					    sexp_l(2, sexp_a(ATOM_TAG),
						   self->access,
						   -1),
					    -1),
				     -1),
			      SEXP_TRANSPORT, 0));
	  A_WRITE(self->file, ssh_format("\n"));
	}
    }
  
  return subject->verifier;
}

static struct lookup_verifier *
make_lsh_host_db(struct spki_context *db,
		 struct address_info *host,
		 int sloppy,
		 struct abstract_write *file)
{
  NEW(lsh_host_db, res);

  res->super.lookup = do_lsh_lookup;
  res->db = db;
  res->access = make_ssh_hostkey_tag(host);
  res->host = host;
  res->sloppy = sloppy;
  res->file = file;
  res->hash = &sha1_algorithm;

  return &res->super;
}

/* Takes an spki_context as argument and returns a lookup_verifier */
static void
do_lsh_verifier(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e UNUSED)
{
  CAST(options_command, self, s);
  CAST_SUBTYPE(spki_context, db, a);
  COMMAND_RETURN(c, make_lsh_host_db(db,
				     self->options->remote,
				     self->options->sloppy,
				     self->options->capture_file));
}

/* Takes an options object as argument and returns a lookup_verifier */

COMMAND_SIMPLE(lsh_verifier_command)
{
  CAST(lsh_options, options, a);

  return
    & make_options_command(options,
			   do_lsh_verifier)->super;
}

/* list-of-public-keys -> login-command */
static void do_lsh_login(struct command *s,
			 struct lsh_object *a,
			 struct command_continuation *c,
			 struct exception_handler *e UNUSED)
{
  CAST(options_command, self, s);
  CAST_SUBTYPE(object_list, keys, a);

  COMMAND_RETURN(c,
		 make_client_userauth(ssh_format("%lz", self->options->user),
				      ATOM_SSH_CONNECTION,
				      (LIST_LENGTH(keys)
				       ? make_object_list
				         (2, 
					  make_client_publickey_auth(keys),
					  make_client_password_auth(), 
					  -1)
				       : make_object_list(1, make_client_password_auth(), 
							  -1))));
}

/* (login options publi-keys connection) */
COMMAND_SIMPLE(lsh_login_command)
{
  CAST(lsh_options, options, a);

  return
    & make_options_command(options,
			   do_lsh_login)->super;
}

/* GABA:
   (expr
     (name make_lsh_connect)
     (params
       (connect object command)
       (handshake object handshake_info)
       (userauth_service object command)
       (requests object object_list))
     (expr (lambda (options)
              ; What to do with the service
	     ((progn requests)
	       ; Initialize service
	       (init_connection_service
	         ; Perform the userauth protocol to login and request
		 ; the ssh-connection service.
		 (lsh_login options (options2identities options)
		   ; Request the userauth service
		   (userauth_service
		     ; Start the ssh transport protocol
	             (connection_handshake
		       handshake
		       (options2verifier options
				         (options2known_hosts options))
 		       ; Connect using tcp
		       (connect (options2remote options))))))))))
*/

/* GABA:
   (expr
     (name make_start_session)
     (params
       (open_session object command)
       (requests object object_list))
     (expr (lambda (connection)
       ((progn requests)
         ; Create a "session" channel
         (open_session connection)))))
*/

/* Requests a shell, and connects the channel to our stdio. */
/* GABA:
   (expr
     (name start_shell)
     (super command)
     (expr
       (lambda (session)
          (client_start_io (request_shell session)))))
*/

/* Parse the argument for -R and -L */
static int
parse_forward_arg(char *arg,
		  UINT32 *listen_port,
		  struct address_info **target)
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

#define ARG_NOT 0x400

#define OPT_NO_PUBLICKEY 0x201

#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204

#define OPT_HOST_DB 0x205

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },
  { "user", 'l', "User name", 0, "Login as this user.", 0 },
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "no-publickey", OPT_NO_PUBLICKEY, NULL, 0,
    "Don't try publickey user authentication.", 0 },
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/known_hosts", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new hostkey is received, append an ACL expressing trust in the key. "
    "In sloppy mode, the default is ~/.lsh/captured_keys.", 0 },
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
      argp_error(state, "Providing a remote command on the command line is not supported yet.");
      break;

    case ARGP_KEY_END:
      {
	if (!self->home)
	  {
	    argp_error(state, "No home directory. Please set HOME in the environment.");
	    break;
	  }
	  
	if (!self->user)
	  {
	    argp_error(state, "No user name given. Use the -l option, or set LOGNAME in the environment.");
	    break;
	  }

	{
	  struct lsh_string *tmp = NULL;
	  const char *s = NULL;
	  
	  if (self->capture)
	    s = self->capture;
	  else if (self->sloppy)
	    {
	      tmp = ssh_format("%lz/.lsh/captured_keys%c", self->home, 0);
	      s = tmp->data;
	    }
	  if (s)
	    {
	      struct io_fd *f
		= io_write_file(self->backend, s,
				O_CREAT | O_APPEND | O_WRONLY,
				0600, 500, NULL,
				make_report_exception_handler(EXC_IO, EXC_IO,
							      "Writing new ACL: ",
							      &default_exception_handler,
							      HANDLER_CONTEXT));
	      if (f)
		self->capture_file = &f->write_buffer->super;
	      else
		{
		  werror("Failed to open '%z' (errno = %i): %z.\n",
			 s, errno, STRERROR(errno));
		}
	    }
	  lsh_string_free(tmp);
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

	    struct command *get_pty = NULL;
	  
	    struct object_list *session_requests;
      
#if WITH_PTY_SUPPORT
	    if (self->with_pty)
	      {
		if (tty_fd < 0)
		  {
		    werror("lsh: No tty available.\n");
		  }
		else
		  {
		    if (! (remember_tty(tty_fd)
			   && (get_pty = make_pty_request(tty_fd))))
		      {
			werror("lsh: Can't use tty (probably getattr or atexit() failed.\n");
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

	break;
      }

    case 'p':
      self->port = arg;
      break;

    case 'l':
      self->user = arg;
      break;

    case 'i':
      self->identity = optarg;
      break;

    case OPT_NO_PUBLICKEY:
      self->publickey = 0;
      break;

    case OPT_HOST_DB:
      self->known_hosts = optarg;
      break;
      
    case OPT_SLOPPY:
      self->sloppy = 1;
      break;

    case OPT_STRICT:
      self->sloppy = 0;
      break;

    case OPT_CAPTURE:
      self->capture = arg;
      break;
      
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
#if 0
      if (exc->fd)
	close_fd_nicely(exc->fd);
#endif 
      *self->status = EXIT_FAILURE;
      
      werror("lsh: %z, (errno = %i)\n", e->msg, exc->error);
    }
  else
    switch(e->type)
      {
      case EXC_RESOLVE:
      case EXC_AUTH:
      case EXC_SERVICE:
      case EXC_SEXP_SYNTAX:
      case EXC_SPKI_TYPE:
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
  struct alist *algorithms;
  
  /* FIXME: A single exception handler everywhere seems a little to
   * crude. */
  struct exception_handler *handler
    = make_lsh_default_handler(&lsh_exit_code, &default_exception_handler,
			       HANDLER_CONTEXT);

  /* FIXME: Why not allocate backend statically? */
  NEW(io_backend, backend);
  init_backend(backend);

  /* Attempt to open a tty */
  lsh_open_tty();
  
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  r = make_reasonably_random();

  /* FIXME: Is this really used? */
  algorithms = many_algorithms(1,
			       ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
			       make_dh_client(make_dh1(r)),
			       -1);

  options = make_options(algorithms, backend, r, handler, &lsh_exit_code);

  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);
  
  {
    struct lsh_object *o =
      make_lsh_connect(
	make_simple_connect(backend, NULL),
	make_handshake_info(CONNECTION_CLIENT,
			    "lsh - a free ssh",
			    SSH_MAX_PACKET,
			    r,
			    algorithms,
			    make_simple_kexinit(
			      r,
			      make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
					    -1),
			      make_int_list(1, ATOM_SSH_DSS, -1),
			      options->super.crypto_algorithms,
			      options->super.mac_algorithms,
			      options->super.compression_algorithms,
			      make_int_list(0, -1)),
			    NULL),
	make_request_service(ATOM_SSH_USERAUTH),
	queue_to_list(&options->actions));
    
    CAST_SUBTYPE(command, lsh_connect, o);

    COMMAND_CALL(lsh_connect, options, &discard_continuation,
		 handler);
	
  } 

  io_run(backend);
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  
  return lsh_exit_code;
}
