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
#include "randomness.h"
#include "service.h"
#include "ssh.h"
#include "tcpforward.h"
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

#include "getopt.h"

#include "lsh.c.x"

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

void usage(void) NORETURN;

void usage(void)
{
  werror("lsh [options] host\n"
	 " -p,  --port=PORT\n"
	 " -l,  --user=NAME\n"
	 " -c,  --crypto=ALGORITHM\n"
	 " -z,  --compression=ALGORITHM\n"
	 "      --mac=ALGORITHM\n"
#if WITH_PTY_SUPPORT
	 " -t,  Request a remote pty\n"
	 " -nt, Don't request a remote tty\n"
	 " -g,  Allow remote access to forwarded ports\n"
	 " -ng, Disallow remote access to forwarded ports (default)\n"
#endif /* WITH_PTY_SUPPORT */
	 " -q,  --quiet\n"
	 " -v,  --verbose\n"
	 "      --debug\n"
#if WITH_TCP_FORWARD
	 " -L   listen-port:host:port    Forward local port\n"
	 " --forward-local-port listen-port:host:port\n"
#if 0
	 " -R,  listen-port_host:port   Forward remote port\n"
	   " --forward-remote-port listen-port_host:port\n"
#endif
#endif /* WITH_TCP_FORWARD */
	 " -N,  --nop   Don't start a remote shell\n"
	 );
  exit(1);
}

/* GABA:
   (class
     (name fake_host_db)
     (super lookup_verifier)
     (vars
       (algorithm object signature_algorithm)))
*/

static struct verifier *do_host_lookup(struct lookup_verifier *c,
				       struct lsh_string *key)
{
  CAST(fake_host_db, closure, c);

  return MAKE_VERIFIER(closure->algorithm, key->length, key->data);
}

static struct lookup_verifier *make_fake_host_db(struct signature_algorithm *a)
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
       (init_connection "&connection_service.super")
       (die_on_null "&command_die_on_null.super"))
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
	           (handshake (die_on_null (connect port))))))))))
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

/* Window size for the session channel */
#define WINDOW_SIZE (SSH_MAX_PACKET << 3)

int main(int argc, char **argv)
{
  char *host = NULL;
  char *user = NULL;
  char *port = "ssh";
  int preferred_crypto = 0;
  int preferred_compression = 0;
  int preferred_mac = 0;
  /* int term_width, term_height, term_width_pix, term_height_pix; */
  int not;
#if WITH_PTY_SUPPORT
  int tty = -1;
  int reset_tty = 0;
  struct termios tty_mode;
  
  int use_pty = -1; /* Means default */
#endif /* WITH_PTY_SUPPORT */

  struct object_queue actions;

  int shell_flag = 1;
  int forward_gateway = 0;
  int remote_forward = 0;
  
  int option;

  int lsh_exit_code = 0;

  struct address_info *remote;
  
  struct randomness *r;
  struct diffie_hellman_method *dh;
  struct keyexchange_algorithm *kex;
  struct alist *algorithms;
  struct make_kexinit *make_kexinit;
  struct lookup_verifier *lookup;

  struct command *get_pty = NULL;
  
  /* int in, out, err; */

  NEW(io_backend, backend);

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  r = make_reasonably_random();
  dh = make_dh1(r);

  /* No randomness is needed for verifying signatures */
  lookup = make_fake_host_db(make_dsa_algorithm(NULL)); 

  kex = make_dh_client(dh, lookup);
  algorithms = many_algorithms(2, 
			       ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, kex,
			       ATOM_SSH_DSS, make_dsa_algorithm(r),
			       -1);

  not = 0;

  object_queue_init(&actions);
  
  for (;;)
    {
      struct option options[] =
      {
	{ "verbose", no_argument, NULL, 'v' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "debug", no_argument, &debug_flag, 1},
	{ "port", required_argument, NULL, 'p' },
	{ "user", required_argument, NULL, 'l' },
	{ "crypto", required_argument, NULL, 'c' },
	{ "compression", optional_argument, NULL, 'z'},
	{ "mac", required_argument, NULL, 'm' },
#if WITH_TCP_FORWARD
	{ "forward-local-port", required_argument, NULL, 'L'},
	{ "forward-remote-port", required_argument, NULL, 'R'},
#endif /* WITH_TCP_FORWARD */
	{ "nop", no_argument, &shell_flag, 0 },
	{ NULL }
      };
      
      option = getopt_long(argc, argv, "+c:l:np:qgtvz:L:R:N", options, NULL);
      switch(option)
	{
	case -1:
	  goto options_done;
	case 0:
	case 'n':
	  break;
	case 'p':
	  port = optarg;
	  break;
	case 'l':
	  user = optarg;
	  break;
	case 'q':
	  quiet_flag = 1;
	  break;
	case 't':
#if WITH_PTY_SUPPORT
	  use_pty = !not;
#endif /* WITH_PTY_SUPPORT */
	  break;
	case 'g':
	  forward_gateway = !not;
	  break;
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'c':
	  preferred_crypto = lookup_crypto(algorithms, optarg);
	  if (!preferred_crypto)
	    {
	      werror("lsh: Unknown crypto algorithm '%z'.\n", optarg);
	      return EXIT_FAILURE;
	    }
	  break;
	case 'z':
	  if (!optarg)
	    optarg = "zlib";
	
	  preferred_compression = lookup_compression(algorithms, optarg);
	  if (!preferred_compression)
	    {
	      werror("lsh: Unknown compression algorithm '%z'.\n", optarg);
	      return EXIT_FAILURE;
	    }
	  break;
	case 'm':
	  preferred_mac = lookup_mac(algorithms, optarg);
	  if (!preferred_mac)
	    {
	      werror("lsh: Unknown message authentication algorithm '%z'.\n",
		      optarg);
	      return EXIT_FAILURE;
	    }
	  break;
	case 'L':
	  {
	    UINT32 listen_port;
	    struct address_info *target;

	    if (!parse_forward_arg(optarg, &listen_port, &target))
	      usage();

	    object_queue_add_tail(&actions,
				  &forward_local_port
				  (backend,
				   make_address_info((forward_gateway
						      ? NULL
						      : ssh_format("%lz", "127.0.0.1")),
						     listen_port),
				   target)->super);
	  }
	  break;
	case 'R':
	  {
	    UINT32 listen_port;
	    struct address_info *target;

	    if (!parse_forward_arg(optarg, &listen_port, &target))
	      usage();

	    object_queue_add_tail(&actions,
				  &forward_remote_port
				  (backend,
				   make_address_info((forward_gateway
						      /* FIXME: Is NULL an ok value? */
						      ? ssh_format("%lz", "0.0.0.0")
						      : ssh_format("%lz", "127.0.0.1")),
						     listen_port),
				   target)->super);
	    remote_forward = 1;
	  }
	  break;
	case '?':
	  usage();
	}
      not = (option == 'n');
    }
 options_done:
  
  if ( (argc - optind) < 1)
    usage();

  host = argv[optind];
  if (!user)
    user = getenv("LOGNAME");

  if (!user)
    {
      werror("lsh: No user name.\n"
	     "Please use the -l option, or set LOGNAME in the environment\n");
      return EXIT_FAILURE;
    }
  
  remote = make_address_info_c(host, port);
  if (!remote)
    {
      werror("lsh: Invalid port or service\n");
      return EXIT_FAILURE;
    }

  init_backend(backend);
  
  if (shell_flag)
    {
      int in;
      int out;
      int err;

      struct object_list *session_requests;
      
#if WITH_PTY_SUPPORT
      if (use_pty < 0)
	use_pty = 1;

      if (use_pty)
	{
	  tty = open("/dev/tty", O_RDWR);
      
	  if (tty < 0)
	    {
	      werror("lsh: Failed to open tty (errno = %i): %z\n",
		     errno, STRERROR(errno));
	      use_pty = 0;
	    }
	  else
	    {
	      reset_tty = tty_getattr(tty, &tty_mode);
	      get_pty = make_pty_request(tty);
	    }
	}
#endif /* WITH_PTY_SUPPORT */
      /* FIXME: We need a non-varargs constructor for lists. */
#if WITH_PTY_SUPPORT
      if (get_pty)
	session_requests = make_object_list(2, get_pty, start_shell(), -1);
      else
#endif
	session_requests = make_object_list(1, start_shell(), -1);

      in = STDIN_FILENO;
      out = STDOUT_FILENO;
  
      if ( (err = dup(STDERR_FILENO)) < 0)
	{
	  werror("Can't dup stderr: %z\n", STRERROR(errno));
	  return EXIT_FAILURE;
	}

      set_error_stream(STDERR_FILENO, 1);
  
      /* Exit code if no session is established */
      lsh_exit_code = 17;

      object_queue_add_tail
	(&actions,
	 make_start_session
	 (make_open_session_command(make_client_session
				    (io_read(make_io_fd(backend, in), NULL, NULL),
				     io_write(make_io_fd(backend, out),
					      BLOCK_SIZE, NULL),
				     io_write(make_io_fd(backend, err),
					      BLOCK_SIZE, NULL),
				     WINDOW_SIZE,
				     &lsh_exit_code)),
	  session_requests));
    }

#if WITH_TCP_FORWARD
  if (remote_forward)
    object_queue_add_tail
      (&actions,
       &make_install_fix_channel_open_handler
       (ATOM_FORWARDED_TCPIP, &channel_open_forwarded_tcpip)->super);
#endif
  
  if (object_queue_is_empty(&actions))
    werror("lsh: No actions given. Exiting.\n");
  else
    {
      make_kexinit
	= make_simple_kexinit(r,
			      make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
					    -1),
			      make_int_list(1, ATOM_SSH_DSS, -1),
			      (preferred_crypto
			       ? make_int_list(1, preferred_crypto, -1)
			       : default_crypto_algorithms()),
			      (preferred_mac
			       ? make_int_list(1, preferred_mac, -1)
			       : default_mac_algorithms()),
			      (preferred_compression
			       ? make_int_list(1, preferred_compression, -1)
			       : default_compression_algorithms()),
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
			      make_client_userauth(ssh_format("%lz", user),
						   ATOM_SSH_CONNECTION),
			      queue_to_list(&actions));

	CAST_SUBTYPE(command, client_connect, o);
	int res = COMMAND_CALL(client_connect, remote, NULL);

	/* We can free the queue nodes now */
	KILL_OBJECT_QUEUE(&actions);

	if (res)
	  {
	    werror("lsh.c: connection failed, res = %i\n", res);
	    return 17;
	  }
      }
      io_run(backend);

      /* FIXME: Perhaps we have to reset the stdio file descriptors to
       * blocking mode? */
    }
  
#if WITH_PTY_SUPPORT
  if (reset_tty)
    tty_setattr(tty, &tty_mode);
#endif
  
  return lsh_exit_code;
}
