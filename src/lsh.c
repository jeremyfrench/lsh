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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "algorithms.h"
#include "alist.h"
#include "atoms.h"
#include "channel.h"
#include "charset.h"
#include "client.h"
#include "client_keyexchange.h"
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "randomness.h"
#include "service.h"
#include "ssh.h"
#include "userauth.h"
#include "werror.h"
#include "xalloc.h"
#include "compress.h"

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "getopt.h"

#include "lsh.c.x"

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

void usage(void) NORETURN;

void usage(void)
{
  wwrite("lsh [options] host\n"
	 " -p,  --port=PORT\n"
	 " -l,  --user=NAME\n"
	 " -c,  --crypto=ALGORITHM\n"
	 " -z,  --compression=ALGORITHM\n"
	 "      --mac=ALGORITHM\n"
	 " -q,  --quiet\n"
	 " -v,  --verbose\n"
	 "      --debug\n");
  exit(1);
}

/* CLASS:
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

int main(int argc, char **argv)
{
  char *host = NULL;
  char *user = NULL;
  char *port = "ssh";
  int preferred_crypto = 0;
  int preferred_compression = 0;
  int preferred_mac = 0;
  
  int not;
  
  int option;

  int lsh_exit_code;
  
  struct sockaddr_in remote;

  struct randomness *r;
  struct diffie_hellman_method *dh;
  struct keyexchange_algorithm *kex;
  struct alist *algorithms;
  struct make_kexinit *make_kexinit;
  struct packet_handler *kexinit_handler;
  struct lookup_verifier *lookup;
  struct ssh_service *service;

  int in, out, err;

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
  
  while(1)
    {
      static struct option options[] =
      {
	{ "verbose", no_argument, NULL, 'v' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "debug", no_argument, &debug_flag, 1},
	{ "port", required_argument, NULL, 'p' },
	{ "user", required_argument, NULL, 'l' },
	{ "crypto", required_argument, NULL, 'c' },
	{ "compression", optional_argument, NULL, 'z'},
	{ "mac", required_argument, NULL, 'm' },
	{ NULL }
      };
      
      option = getopt_long(argc, argv, "+c:l:np:qvz::", options, NULL);
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
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'c':
	  preferred_crypto = lookup_crypto(algorithms, optarg);
	  if (!preferred_crypto)
	    {
	      werror("lsh: Unknown crypto algorithm '%s'.\n", optarg);
	      exit(1);
	    }
	  break;
	case 'z':
	  if (!optarg)
	    optarg = "zlib";
	
	  preferred_compression = lookup_compression(algorithms, optarg);
	  if (!preferred_compression)
	    {
	      werror("lsh: Unknown compression algorithm '%s'.\n", optarg);
	      exit(1);
	    }
	  break;
	case 'm':
	  preferred_mac = lookup_mac(algorithms, optarg);
	  if (!preferred_mac)
	    {
	      werror("lsh: Unknown message authentication algorithm '%s'.\n",
		      optarg);
	      exit(1);
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
      wwrite("lsh: No user name.\n"
	     "Please use the -l option, or set LOGNAME in the environment\n");
      exit(EXIT_FAILURE);
    }

  if (!get_inaddr(&remote, host, port, "tcp"))
    {
      wwrite("No such host or service\n");
      exit(1);
    }

  in = STDIN_FILENO;
  out = STDOUT_FILENO;
  
  if ( (err = dup(STDERR_FILENO)) < 0)
    {
      werror("Can't dup stderr: %s\n", strerror(errno));
      return EXIT_FAILURE;
    }

  init_backend(backend);
  
  set_error_stream(STDERR_FILENO, 1);
  
  make_kexinit
    = make_simple_kexinit(r,
			  make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, -1),
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
  
  service = make_connection_service
    (make_alist(0, -1),
     make_alist(0, -1),
     make_client_startup(io_read(backend, in, NULL, NULL),
			 io_write(backend, out, BLOCK_SIZE, NULL),
			 io_write(backend, err, BLOCK_SIZE, NULL),
			 ATOM_SHELL, ssh_format(""), &lsh_exit_code));
  
  kexinit_handler = make_kexinit_handler
    (CONNECTION_CLIENT,
     make_kexinit, algorithms,
     request_service(ATOM_SSH_USERAUTH, 
		     make_client_userauth(ssh_format("%lz", user),
					  ATOM_SSH_CONNECTION,
					  service)));
  
  if (!io_connect(backend, &remote, NULL,
		  make_client_callback(backend,
				       "lsh - a free ssh",
				       SSH_MAX_PACKET,
				       r, make_kexinit,
				       kexinit_handler)))
    {
      werror("lsh: Connection failed: %s\n", strerror(errno));
      return 1;
    }

  /* Exit code if no session is established */
  lsh_exit_code = 17;
  
  io_run(backend);

  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */

  return lsh_exit_code;
}

  
