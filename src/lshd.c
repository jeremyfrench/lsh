/* lshd.c
 *
 * main server program.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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
#include "crypto.h"
#include "format.h"
#include "io.h"
#include "password.h"
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

void usage(void)
{
  wwrite("lshd [options]\n"
	 " -p,  --port=PORT\n"
	 " -h,  --hostkey=KEYFILE\n"
	 " -c,  --crypto=ALGORITHM\n"
	 " -z,  --compression=ALGORITHM\n"
	 "      --mac=ALGORITHM\n"
	 " -q,  --quiet\n"
	 " -v,  --verbose\n"
	 "      --debug\n");
  exit(1);
}

#if 0
struct signer *secret_key;
struct lsh_string *public_key;

/* A key generated by gnupg */
static void init_host_key(struct randomness *r)
{
  mpz_t p, q, g, y, a;
  mpz_t tmp;
  struct lsh_string *s;
  
  mpz_init_set_str(p,
		   "BC7797D55CF2449CA4B02396246AF5C75CA38C52B6F2E543"
		   "6754198B137B25B0A81DFE269D5CDFD0AEA290A32BA5B918"
		   "B58D64762D40EAA8D70F282B3AC4A7771171B1B1D1AE89F4"
		   "1CD091FE95A6F42A2340081F9E97A4B5F953DE223F10F878"
		   "4C0619A9979643E5325DF71C9C088F3BC82FA0A6C47B5C64"
		   "BC07A31B9CDB2B07", 16);
  mpz_init_set_str(q,
		   "867F7E6563B3FAF19B65C83E9B843150C5CC2201", 16);
  mpz_init_set_str(g,
		   "7FA83EAEDFD8679A4A80C869AD7E353F3B517569C2079C79"
		   "97EA6655764581B073F71AA15C07A789AEB213B106741AAB"
		   "CA81B8300B1F8510D3CD1C3D9D7D11640C1608E8E2E71527"
		   "68B8FDCB5544E29A020D14CC5C12E264C59E57E9F6832DA7"
		   "10B805CD9866C1110D60069D31D5A72D1A1ED96F2B11CFEF"
		   "7AB347F0632CB0C7", 16);
  mpz_init_set_str(y,
		   "2DA5B458DF3616097FA22DB6BDDD31A29E532054D4C208F7"
		   "EBF63EB2476E8E98E0885CFBC5669B56EC834E42058E8BCF"
		   "C259CA1BE981D7721306709499DE27E7B13F62359D9520D1"
		   "3D73C62E8E5C5F6B8E2C70217EC3B557FBCB98535BE3C6EE"
		   "0C71DEC1FE9C6791D3780DD8D593D5030969D303A5818B01"
		   "C4B855C07E8C4F64", 16);
  mpz_init_set_str(a,
		   "295190AEDBBD6EBD2F817F7D8CCC8B0095DCD82E", 16);

  mpz_init_set(tmp, g);
  mpz_powm(tmp, tmp, a, p);
  if (mpz_cmp(tmp, y))
    fatal("Test key invalid\n");

  mpz_clear(tmp);

  public_key = ssh_format("%a%n%n%n%n", ATOM_SSH_DSS, p, q, g, y);
  s = ssh_format("%n", a);

  secret_key = MAKE_SIGNER(make_dss_algorithm(r),
			   public_key->length, public_key->data,
			   s->length, s->data);

  if (!secret_key)
    fatal("Can't parse secret key\n");

  lsh_string_free(s);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(g);
  mpz_clear(y);
  mpz_clear(a);
}
#endif

/* FIXME: We should have some more general functions for reading private keys. */

/* CLASS:
   (class
     (name read_key)
     (super sexp_handler)
     (vars
       (random object randomness)
       (secret pointer (object signer))
       (public pointer (string))))
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
  if (! (e && sexp_check_type(e, "dss", &i)))
    {
      werror("lshd: Unknown key type (only dss is supported)\n");
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
	  struct signer *secret;
	  	  
	  s = ssh_format("%n", x);
	  
	  secret = MAKE_SIGNER(make_dss_algorithm(closure->random),
			       public->length, public->data,
			       s->length, s->data);
	  assert(secret);
	  lsh_string_free(s);

	  *closure->public = public;
	  *closure->secret = secret;

	  verbose("lshd: Using (public) hostkey:\n  p=");
	  verbose_mpz(p);
	  verbose("\n  q=");
	  verbose_mpz(q);
	  verbose("\n  g=");
	  verbose_mpz(g);
	  verbose("\n  y=");
	  verbose_mpz(y);
	  verbose("\n");
		  
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
			 struct lsh_string **public,
			 struct signer **secret,
			 struct randomness *r)
{
  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      werror("lshd: Could not open %s (errno = %d): %s\n",
	     name, errno, strerror(errno));
      return 0;
    }
  else
    {
      int res;
      
      NEW(read_key, handler);
      handler->super.handler = do_read_key;

      handler->random = r;
      handler->public = public;
      handler->secret = secret;
      
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
  
int main(int argc, char **argv)
{
  char *host = NULL;  /* Interface to bind */
  char *port = "ssh";
  char *hostkey = "/etc/lsh_host_key";

  struct lsh_string *public_key = NULL; 
  struct signer *secret_key = NULL;
  
  int option;

  int preferred_crypto = 0;
  int preferred_compression = 0;
  int preferred_mac = 0;

  struct sockaddr_in local;

  struct reap *reaper;
  
  struct randomness *r;
  struct diffie_hellman_method *dh;
  struct keyexchange_algorithm *kex;
  struct alist *algorithms;
  struct make_kexinit *make_kexinit;
  struct packet_handler *kexinit_handler;

  NEW(io_backend, backend);

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  r = make_reasonably_random();
  dh = make_dh1(r);
  
  algorithms = many_algorithms(1,
			       ATOM_SSH_DSS, make_dss_algorithm(r),
			       -1);

  while(1)
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
	{ NULL }
      };
      
      option = getopt_long(argc, argv, "c:h:p:qvz::", options, NULL);
      switch(option)
	{
	case -1:
	  goto options_done;
	case 0:
	  break;
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
	    
	case '?':
	  usage();
	}
    }
 options_done:

  if ( (argc - optind) != 0)
    usage();

  /* Read the hostkey */
  if (!read_host_key(hostkey, &public_key, &secret_key, r))
    {
      return EXIT_FAILURE;
    }

  if (!get_inaddr(&local, host, port, "tcp"))
    {
      fprintf(stderr, "No such host or service");
      return EXIT_FAILURE;
    }

  init_backend(backend);
  reaper = make_reaper();

  kex = make_dh_server(dh, public_key, secret_key);

  ALIST_SET(algorithms, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, kex);

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
			       make_server_session_service
			       (make_alist(0, -1),
				make_alist(1, ATOM_SHELL,
					   make_shell_handler(backend,
							      reaper),
					   -1)),
			       -1)),
		   -1)),
       -1)));
     
  if (!io_listen(backend, &local, 
	    make_server_callback(backend,
				 "lsh - a free ssh",
				 SSH_MAX_PACKET,
				 r, make_kexinit,
				 kexinit_handler)))
    {
      werror("lsh: Connection failed: %s\n", strerror(errno));
      return 1;
    }
  
  reaper_run(reaper, backend);

  return 0;
}
