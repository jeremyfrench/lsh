/* lshd.c
 *
 * main server program.
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
#include "connection_commands.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "io_commands.h"
#include "server_password.h"
#include "server_session.h"
#include "randomness.h"
#include "reaper.h"
#include "server.h"
#include "server_keyexchange.h"
#include "sexp.h"
#include "ssh.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"
#include "compress.h"
#include "server_pty.h"

#include "getopt.h"

#include "lshd.c.x"

#include <assert.h>

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

void usage(void) NORETURN;

#define OPT_SSH1_FALLBACK -2

void usage(void)
{
  werror("lshd [options]\n"
	 " -p,  --port=PORT\n"
	 " -h,  --hostkey=KEYFILE\n"
	 " -c,  --crypto=ALGORITHM\n"
	 " -z,  --compression[=ALGORITHM]\n"
	 "      --mac=ALGORITHM\n"
	 " -q,  --quiet\n"
#if WITH_SSH1_FALLBACK
         "      --ssh1-fallback=SSHD\n"
#endif
	 " -v,  --verbose\n"
	 "      --debug\n");
  exit(1);
}


/* FIXME: We should have some more general functions for reading
 * private keys. */

/* GABA:
   (class
     (name read_key)
     (super sexp_handler)
     (vars
       (random object randomness)
       ;; Maps hostkey algorithm to a keyinfo structure
       (keys object alist)))
*/

static int do_read_key(struct sexp_handler *h, struct sexp *private)
{
  CAST(read_key, closure, h);
  struct sexp_iterator *i;
  struct sexp *e;
  mpz_t p, q, g, y, x;

  int res;
  
  if (!sexp_check_type(private, "private-key", &i))
    {
      werror("lshd: Host key file does not contain a private key.");
      return LSH_FAIL | LSH_DIE;
    }

  e = SEXP_GET(i);
  if (! (e && sexp_check_type(e, "dsa", &i)))
    {
      werror("lshd: Unknown key type (only dsa is supported)\n");
      return LSH_FAIL | LSH_DIE;
    }

  mpz_init(p);
  mpz_init(q);
  mpz_init(g);
  mpz_init(y);
  mpz_init(x);

  if (sexp_get_un(i, "p", p)
      && sexp_get_un(i, "q", q)
      && sexp_get_un(i, "g", g)
      && sexp_get_un(i, "y", y)
      && sexp_get_un(i, "x", x)
      && !SEXP_GET(i))
    {
      /* Test key */
      mpz_t tmp;
      struct lsh_string *s;
      
      mpz_init_set(tmp, g);
      mpz_powm(tmp, tmp, x, p);
      if (mpz_cmp(tmp, y))
	{
	  werror("lshd: Host key doesn't work.\n");
	  mpz_clear(tmp);

	  res = LSH_FAIL | LSH_DIE;
	}
      else
	{
	  struct lsh_string *public
	    = ssh_format("%a%n%n%n%n", ATOM_SSH_DSS, p, q, g, y);
	  struct signer *private;
	  	  
	  s = ssh_format("%n", x);
	  
	  private = MAKE_SIGNER(make_dsa_algorithm(closure->random),
				public->length, public->data,
				s->length, s->data);
	  assert(private);
	  lsh_string_free(s);
	  
	  /* FIXME: Check if we already have a key for this algorithm,
	   * and warn about multiple keys. */
	  ALIST_SET(closure->keys, ATOM_SSH_DSS,
		    make_keypair_info(public, private));

#if DATAFELLOWS_SSH2_SSH_DSA_KLUDGE
	  ALIST_SET(closure->keys, ATOM_SSH_DSS_KLUDGE,
		    make_keypair_info(public,
				      make_dsa_signer_kludge(private)));
#endif
	  
	  verbose("lshd: Using (public) hostkey:\n"
		  "  p=%hn\n"
		  "  q=%hn\n"
		  "  g=%hn\n"
		  "  y=%hn\n",
		  p, q, g, y);
		  
	  res = LSH_OK | LSH_CLOSE;
	}
    }
  else
    res = LSH_FAIL | LSH_DIE;

  /* Cleanup */
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(g);
  mpz_clear(y);
  mpz_clear(x);

  return res;
}

static int read_host_key(const char *name,
			 struct alist *keys,
			 struct randomness *r)
{
  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      werror("lshd: Could not open %z (errno = %i): %z\n",
	     name, errno, strerror(errno));
      return 0;
    }
  else
    {
      int res;
      
      NEW(read_key, handler);
      handler->super.handler = do_read_key;

      handler->random = r;
      handler->keys = keys;
      
      res = blocking_read(fd, make_read_sexp(&handler->super,
					     2000, SEXP_TRANSPORT, 0));
      close(fd);

      KILL(handler);
      
      if (LSH_FAILUREP(res))
	{
	  werror("lshd: Invalid host key.\n");
	  return 0;
	}

      return 1;
    }
}

/* Invoked when the client requests the userauth service. */
/* GABA:
   (expr
     (name lshd_services)
     (params 
       (userauth object command) )
     (expr
       (lambda (connection)
         ((userauth connection) connection))))
*/

/* GABA:
   (expr
     (name lshd_listen)
     (globals
       (log "&io_log_peer_command.super.super"))
     (params
       (listen object command)
       (handshake object command)
       (services object command) )
     (expr (lambda (port)
             (services (handshake (log (listen port)))))))
*/

int main(int argc, char **argv)
{
  char *host = NULL;  /* Interface to bind */
  char *port = "ssh";
  /* TODO: this should probably use sysconfdir */  
  char *hostkey = "/etc/lsh_host_key";

#if WITH_SSH1_FALLBACK
  char *sshd1 = NULL;
#endif
  
  struct alist *keys;
  
  int option;

  int preferred_crypto = 0;
  int preferred_compression = 0;
  int preferred_mac = 0;

  struct address_info *local;

  struct reap *reaper;
  
  struct randomness *r;
  struct diffie_hellman_method *dh;
  struct keyexchange_algorithm *kex;
  struct alist *algorithms;
  struct make_kexinit *make_kexinit;

  NEW(io_backend, backend);

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  r = make_reasonably_random();
  dh = make_dh1(r);
  
  algorithms = many_algorithms(1,
			       ATOM_SSH_DSS, make_dsa_algorithm(r),
			       -1);

  for (;;)
    {
      static struct option options[] =
      {
	{ "verbose", no_argument, NULL, 'v' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "debug", no_argument, &debug_flag, 1},
	{ "port", required_argument, NULL, 'p' },
	{ "crypto", required_argument, NULL, 'c' },
	{ "compression", optional_argument, NULL, 'z'},
	{ "mac", required_argument, NULL, 'm' },
	{ "hostkey", required_argument, NULL, 'h' },
#if WITH_SSH1_FALLBACK
	{ "ssh1-fallback", optional_argument, NULL, OPT_SSH1_FALLBACK},
#endif
	{ NULL }
      };
      
      option = getopt_long(argc, argv, "c:h:p:qvz::", options, NULL);
      switch(option)
	{
	case -1:
	  goto options_done;
	case 0:
	  break;
#if WITH_SSH1_FALLBACK
	case OPT_SSH1_FALLBACK:
	  sshd1 = optarg ? optarg : SSHD1;
	  break;
#endif
	case 'p':
	  port = optarg;
	  break;
	case 'q':
	  quiet_flag = 1;
	  break;
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'h':
	  hostkey = optarg;
	  break;
	case 'c':
	  preferred_crypto = lookup_crypto(algorithms, optarg);
	  if (!preferred_crypto)
	    {
	      werror("lsh: Unknown crypto algorithm '%z'.\n", optarg);
	      exit(1);
	    }
	  break;
	case 'z':
	  if (!optarg)
	    optarg = "zlib";
	
	  preferred_compression = lookup_compression(algorithms, optarg);
	  if (!preferred_compression)
	    {
	      werror("lsh: Unknown compression algorithm '%z'.\n", optarg);
	      exit(1);
	    }
	  break;
	case 'm':
	  preferred_mac = lookup_mac(algorithms, optarg);
	  if (!preferred_mac)
	    {
	      werror("lsh: Unknown message authentication algorithm '%z'.\n",
		      optarg);
	      exit(1);
	    }
	    
	case '?':
	  usage();
	}
    }
 options_done:

  if ( (argc - optind) != 0)
    usage();

  /* Read the hostkey */
  keys = make_alist(0, -1);
  if (!read_host_key(hostkey, keys, r))
    {
      werror("lshd: Could not read hostkey.\n");
      return EXIT_FAILURE;
    }
  /* FIXME: We should check that we have at aleast one host key.
   * We should also extract the host-key algorithms for which we have keys,
   * instead of hardcoding ssh-dss below. */

  local = make_address_info_c(host, port);
  if (!local)
    {
      werror("lshd: Invalid port or service\n");
      exit (EXIT_FAILURE);
    }

#if 0
  if (!get_inaddr(&local, host, port, "tcp"))
    {
      werror("lshd: No such host or service.\n");
      return EXIT_FAILURE;
    }
#endif
  
#if 0
#if HAVE_SYSLOG
  {
    int option = LOG_PID | LOG_CONS;
    if (foreground_flag)
      {
	option |= LOG_PERROR;
      }
    openlog("lshd", option, LOG_DAEMON);
    syslog_flag = 1;
  }
#endif /* HAVE_SYSLOG */
#endif
 
  init_backend(backend);
  reaper = make_reaper();

  kex = make_dh_server(dh, keys);

  ALIST_SET(algorithms, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, kex);

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
#if 0
  kexinit_handler = make_kexinit_handler
    (CONNECTION_SERVER,
     make_kexinit, algorithms,
     make_meta_service
     (make_alist
      (1, ATOM_SSH_USERAUTH,
       make_userauth_service
       (make_int_list(1, ATOM_PASSWORD, -1),
	make_alist(1, ATOM_PASSWORD,
		   make_unix_userauth
		   (make_alist(1,
			       ATOM_SSH_CONNECTION,
			       make_server_connection_service
			       (make_alist(0, -1),
				make_alist(1
#if WITH_PTY_SUPPORT
					   +1, ATOM_PTY_REQ, make_pty_handler()
#endif /* WITH_PTY_SUPPORT */
					   , ATOM_SHELL, make_shell_handler(backend, reaper),
					   -1),
				backend),
			       -1)),
		   -1)),
       -1)));
#endif
  
  {
    struct lsh_object *o = lshd_listen
      (make_simple_listen(backend, NULL),
       make_handshake_command(CONNECTION_SERVER,
			      "lsh - a free ssh",
			      SSH_MAX_PACKET,
			      r,
			      algorithms,
			      make_kexinit,
#if WITH_SSH1_FALLBACK
			      sshd1 ? make_ssh1_fallback (sshd1) :
#endif /* WITH_SSH1_FALLBACK */
			      NULL),
       make_offer_service
       (make_alist
	(1, ATOM_SSH_USERAUTH,
	 lshd_services(make_userauth_service
		       (make_int_list(1, ATOM_PASSWORD, -1),
			make_alist(1, ATOM_PASSWORD,
				   &unix_userauth.super, -1),
			make_alist(1, ATOM_SSH_CONNECTION,
				   make_server_connection_service
				   (make_alist(0, -1),
				    make_alist
				    (1
#if WITH_PTY_SUPPORT
				     +1, ATOM_PTY_REQ, make_pty_handler()
#endif /* WITH_PTY_SUPPORT */
				     , ATOM_SHELL,
				     make_shell_handler(backend,
							reaper),
				     -1),
				    backend),
				   -1))),
	 -1)));
    
    CAST_SUBTYPE(command, server_listen, o);
    
    int res = COMMAND_CALL(server_listen, local, NULL);
    if (res)
      {
	if (res & LSH_COMMAND_FAILED)
	    werror("lshd: Failed to bind port. (errno = %d) %z\n",
		   errno, strerror(errno));
	else
	  werror("lshd: Unexpected failure from listen: %d\n", res);
	return EXIT_FAILURE;
      }
  }
#if 0
  if (!io_listen(backend, &local, 
		 make_server_callback(backend,
				      "lsh - a free ssh",
#if WITH_SSH1_FALLBACK
				      sshd1 ? make_ssh1_fallback (sshd1) :
#endif /* WITH_SSH1_FALLBACK */
				      NULL,
				      SSH_MAX_PACKET,
				      r, make_kexinit,
				      kexinit_handler)))
    {
      werror("lshd: listen() failed: (errno = %i): %z\n",
	     errno, strerror(errno));
      return 1;
    }
#endif
  
  reaper_run(reaper, backend);

  return 0;
}
