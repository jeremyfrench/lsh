/* lsh-keygen.c
 *
 * Generic key-generation program. Writes a spki-packaged private key
 * on stdout. You would usually pipe this to some other program to
 * extract the public key, encrypt the private key, and save the
 * results in two separate files.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "nettle/dsa.h"
#include "nettle/rsa.h"

#include "algorithms.h"
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "lsh_string.h"
#include "randomness.h"
#include "sexp.h"
#include "spki.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh_argp.h"

#include "lsh-keygen.c.x"

/* Uses a 30-bit public exponetnt for RSA. */
#define E_SIZE 30

/* Option parsing */

const char *argp_program_version
= "lsh-keygen (" PACKAGE_STRING ")";

const char *argp_program_bug_address = BUG_ADDRESS;

enum {
  OPT_SERVER = 0x200,
  OPT_READ_RAW,
  OPT_WRITE_RAW,
  OPT_LABEL,
  OPT_PASSPHRASE,
};

/* GABA:
   (class
     (name lsh_keygen_options)
     (super werror_config)     
     (vars
       ; Mode of operation. 
       (read_raw . int)
       (write_raw . int)
       (server . int)

       ; Key generation options
       ; 'd' means dsa, 'r' rsa
       (algorithm . int)
       (level . int)

       ; Output options
       (public_file string)
       (private_file string)
       (label string)
       (passphrase string)

       (crypto_algorithms object alist)
       (signature_algorithms object alist)

       ; Zero means default, which depends on the --server flag.
       (crypto_name . int)
       (crypto object crypto_algorithm)
       (iterations . uint32_t)))
*/

static struct lsh_keygen_options *
make_lsh_keygen_options(void)
{
  NEW(lsh_keygen_options, self);
  init_werror_config(&self->super);

  self->read_raw = 0;
  self->write_raw = 0;
  self->server = 0;

  self->level = -1;
  self->algorithm = 'r';

  self->public_file = NULL;
  self->private_file = NULL;

  self->label = NULL;

  self->passphrase = NULL;
  self->iterations = 1500;

  self->crypto_algorithms = all_symmetric_algorithms();
  self->signature_algorithms = all_signature_algorithms();

  self->crypto_name = 0;
  self->crypto = NULL;
  
  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "algorithm", 'a', "Algorithm", 0, "DSA or RSA. "
    "Default is to generate RSA keys", 0 },
  { "server", OPT_SERVER, NULL, 0,
    "Use the server's seed-file, and change the default output file "
    "to /etc/lsh_host_key.", 0 },
  { "write-raw", OPT_WRITE_RAW, NULL, 0,
    "Write unencrypted private key to stdout, with no splitting "
    "into private and public key files.", 0 },
  { "read-raw", OPT_READ_RAW, NULL, 0,
    "Don't generate a new key, instead read an unencrypted private key from stdin.", 0 },
  /* FIXME: Split into two options, --length to specify bit size, and
     --nist-level for dsa and backwards compatibility. */

  { "nist-level", 'l', "Security level", 0, "For DSA keys, this is the "
    "NIST security level: Level 0 uses 512-bit primes, level 8 uses "
    "1024 bit primes, and the default is 8. For RSA keys, it's the "
    "bit length of the modulus, and the default is 2048 bits.", 0 },
  { "output-file", 'o', "Filename", 0, "Default is ~/.lsh/identity", 0 },
  { "crypto", 'c', "Algorithm", 0, "Encryption algorithm for the private key file.", 0 },
  { "label", OPT_LABEL, "Text", 0, "Unencrypted label for the key.", 0 },
  { "passphrase", OPT_PASSPHRASE, "Passphrase. This option intended for testing only.", 0, NULL, 0 },
  
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_keygen_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      break;

    case ARGP_KEY_END:
      if (!werror_init(&self->super))
	argp_failure(state, EXIT_FAILURE, errno, "Failed to open log file");

      switch (self->algorithm)
	{
	case 'd':
	  if (self->level < 0)
	    self->level = 8;
	  else if (self->level > 8)
	    argp_error(state, "Security level for DSA should be in the range 0-8.");
	  
	  break;
	case 'r':
	  if (self->level < 0)
	    self->level = 2048;
	  else if (self->level < 512)
	    argp_error(state, "RSA keys should be at the very least 512 bits.");
	  break;
	default:
	  fatal("Internal error!\n");
	}

      if (!self->private_file)
	{
	  if (self->server)
	    {
	      if (mkdir(FILE_LSHD_CONFIG_DIR, 0755) < 0
		  && errno != EEXIST)
		argp_failure(state, EXIT_FAILURE, errno,
			     "Creating directory %s failed.", FILE_LSHD_CONFIG_DIR);

	      self->private_file = make_string(FILE_LSHD_HOST_KEY);
	    }	    
	  else
	    {
	      char *home = getenv(ENV_HOME);
	  
	      if (!home)
		{
		  argp_failure(state, EXIT_FAILURE, 0, "$HOME not set.");
		  return EINVAL;
		}
	      else
		{
		  /* Some duplication with unix_random_user */
		  struct lsh_string *s = ssh_format("%lz/.lsh", home);
		  const char *cs = lsh_get_cstring(s);
		  if (mkdir(cs, 0755) < 0
		      && errno != EEXIST)
		    argp_failure(state, EXIT_FAILURE, errno,
				 "Creating directory %s failed.", cs);

		  lsh_string_free(s);
		  self->private_file = ssh_format("%lz/.lsh/identity", home);
		}
	    }
	}
      self->public_file = ssh_format("%lS.pub", self->private_file);

      /* Default behaviour is to encrypt the key unless running in
	 server mode. */
      if (!self->crypto_name && !self->server)
	{
	  self->crypto_name = ATOM_AES256_CBC;
	  self->crypto = &crypto_aes256_cbc_algorithm;	 
	}
      if (!self->write_raw && self->crypto)
	{
	  if (!self->label)
	    {
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 300
#endif
	      char host[MAXHOSTNAMELEN];
	      const char *name;
	  
	      USER_NAME_FROM_ENV(name);

	      if (!name)
		{
		  argp_failure(state, EXIT_FAILURE, 0,
			       "LOGNAME not set. Please use the -l option.");
		  return EINVAL;
		}

	      if ( (gethostname(host, sizeof(host)) < 0)
		   && (errno != ENAMETOOLONG) )
		argp_failure(state, EXIT_FAILURE, errno,
			     "Can't get the host name. Please use the -l option.");
	      
	      self->label = ssh_format("%lz@%lz", name, host);
	    }
	}
      break;
	  
    case OPT_SERVER:
      self->server = 1;
      break;

    case OPT_READ_RAW:
      self->read_raw = 1;
      break;

    case OPT_WRITE_RAW:
      self->write_raw = 1;
      break;

    case 'l':
	{
	  char *end;
	  long l = strtol(arg, &end, 0);
	      
	  if (!*arg || *end)
	    {
	      argp_error(state, "Invalid security level.");
	      break;
	    }
	  if (l<0) 
	    {
	      argp_error(state, "Security level can't be negative.");
	      break;
	    }
	  self->level = l;
	  break;
	}

    case 'a':
      if (!strcasecmp(arg, "dsa"))
	self->algorithm = 'd';
      else if (!strcasecmp(arg, "rsa"))
	self->algorithm = 'r';
      else
	argp_error(state, "Unknown algorithm. The supported algorithms are "
		   "RSA and DSA.");
      
      break;

    case 'i':
      {
	long i;
	char *end;
	i = strtol(arg, &end, 0);

	if ((end == arg) || *end || (i < 1))
	  {
	    argp_failure(state, EXIT_FAILURE, 0, "Invalid iteration count.");
	    return EINVAL;
	  }
	else if (i > PKCS5_MAX_ITERATIONS)
	  {
	    argp_error(state, "Iteration count ridiculously large (> %d).",
		       PKCS5_MAX_ITERATIONS);
	    return EINVAL;
	  }
	else
	  self->iterations = i;

	break;
      }

    case 'o':
      self->private_file = make_string(arg);
      break;

    case 'c':
      {
	int name = lookup_crypto(self->crypto_algorithms, arg, &self->crypto);

	if (name)
	  self->crypto_name = name;
	else
	  {
	    list_crypto_algorithms(state, self->crypto_algorithms);
	    argp_error(state, "Unknown crypto algorithm '%s'.", arg);
	  }
	break;
      }
      
    case OPT_LABEL:
      self->label = ssh_format("%lz", arg);
      break;
      
    case OPT_PASSPHRASE:
      self->passphrase = ssh_format("%lz", arg);
      break;
    }

  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  NULL,
  ( "Generates a new key pair, splits it into a private and a public key file, "
    "with the private key protected by a passphrase."),
  main_argp_children,
  NULL, NULL
};

static void
progress(void *ctx UNUSED, int c)
{
  char buf[2];
  buf[0] = c; buf[1] = '\0';
  if (c != 'e')
    werror_progress(buf);
}

static struct lsh_string *
dsa_generate_key(unsigned level)
{
  struct dsa_public_key public;
  struct dsa_private_key private;
  struct lsh_string *key = NULL;

  dsa_public_key_init(&public);
  dsa_private_key_init(&private);

  if (dsa_generate_keypair(&public, &private,
			   NULL, lsh_random,
			   NULL, progress,
			   512 + 64 * level))
    {
      key =
	lsh_string_format_sexp(0,
			       "(private-key(dsa(p%b)(q%b)(g%b)(y%b)(x%b)))",
			       public.p, public.q, public.g, public.y,
			       private.x);
    }

  dsa_public_key_clear(&public);
  dsa_private_key_clear(&private);
  return key;
}

static struct lsh_string *
rsa_generate_key(uint32_t bits)
{
  struct rsa_public_key public;
  struct rsa_private_key private;
  struct lsh_string *key = NULL;

  rsa_public_key_init(&public);
  rsa_private_key_init(&private);

  if (rsa_generate_keypair(&public, &private,
			   NULL, lsh_random,
			   NULL, progress,
			   bits, E_SIZE))
    {
      /* FIXME: Use rsa-pkcs1 or rsa-pkcs1-sha1? */
      /* FIXME: Some code duplication with
	 rsa.c:do_rsa_public_spki_key */
      key = lsh_string_format_sexp(0, "(private-key(rsa-pkcs1(n%b)(e%b)"
				   "(d%b)(p%b)(q%b)(a%b)(b%b)(c%b)))",
				   public.n, public.e,
				   private.d, private.p, private.q,
				   private.a, private.b, private.c);
    }
  rsa_public_key_clear(&public);
  rsa_private_key_clear(&private);
  return key;
}


/* Returns 1 for success, 0 for errors. */
static int
check_file(const struct lsh_string *file)
{
  struct stat sbuf;

  if (stat(lsh_get_cstring(file), &sbuf) == 0
      || errno != ENOENT)
    {
      werror("File `%S' already exists.\n"
	     "lsh-keygen doesn't overwrite existing key files.\n"
	     "If you really want to do that, you should delete\n"
	     "the existing files first\n",
	     file);
      return 0;
    }
  return 1;
}

static int
open_file(const struct lsh_string *file)
{
  int fd = open(lsh_get_cstring(file),
                O_CREAT | O_EXCL | O_WRONLY,
                0600);

  if (fd < 0)
    werror("Failed to open `%S'for writing: %e.\n", file, errno);

  return fd;
}

static const struct lsh_string *
process_private(const struct lsh_string *key,
                struct lsh_keygen_options *options)
{
  if (options->crypto)
    {
      CAST_SUBTYPE(mac_algorithm, hmac,
                   ALIST_GET(options->crypto_algorithms, ATOM_HMAC_SHA1));
      assert(hmac);
      
      while (!options->passphrase)
	{
	  struct lsh_string *pw;
	  struct lsh_string *again;
	  
	  pw = interact_read_password(ssh_format("Enter new passphrase: "));
	  if (!pw)
	    {
	      werror("Aborted.");
	      return NULL;
	    }

	  again = interact_read_password(ssh_format("Again: "));
	  if (!again)
	    {
	      werror("Aborted.");
	      lsh_string_free(pw);
	      return NULL;
	    }

	  if (lsh_string_eq(pw, again))
	    options->passphrase = pw;
	  else
	    lsh_string_free(pw);
	  
	  lsh_string_free(again);
	}

      return spki_pkcs5_encrypt(options->label,
				ATOM_HMAC_SHA1,
				hmac,
				options->crypto_name,
				options->crypto,
				10, /* Salt length */
				options->passphrase,
				options->iterations,
				key);
    }
  else
    return key;
}

static struct lsh_string *
process_public(const struct lsh_string *key,
               struct lsh_keygen_options *options)
{
  struct signer *s;
  struct verifier *v;

  /* In the common case that the key was generated (the --read-raw
     option not used), we do a lot of unnecessary work here. But on
     the other hand, we get a check that the generated key is
     syntactically valid. */
  s = spki_make_signer(options->signature_algorithms, key, NULL);
  
  if (!s)
    return NULL;

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  return PUBLIC_SPKI_KEY(v, 1);
}

int
main(int argc, char **argv)
{
  struct lsh_keygen_options *options = make_lsh_keygen_options();

  const struct lsh_string *private;
  int private_fd;
  int res;

  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  /* Try to fail early. */
  if (!options->write_raw)
    if (!(check_file(options->private_file)
	  && check_file(options->public_file)))
      return EXIT_FAILURE;
  
  if (options->server)
    res = random_init_system();
  else
    {
      unix_interact_init(0);
      res = random_init_user(getenv(ENV_HOME));
    }

  if (!res)
    {
      werror("Failed to initialize randomness generator.\n");
      return EXIT_FAILURE;
    }

  /* FIXME: Optionally use interactive keyboard input to get some more
   * entropy */

  if (options->read_raw)
    {
      private = io_read_file_raw(STDIN_FILENO, 2000);
      if (!private)
	{
	  werror("Failed to read key from stdin: %e.\n", errno);
	  return EXIT_FAILURE;
	}
    }
  else
    switch (options->algorithm)
      {
      case 'd':
	private = dsa_generate_key(options->level);
	break;
      case 'r':
	private = rsa_generate_key(options->level);
	break;
      default:
	fatal("Internal error!\n");
      }

  if (options->write_raw)
    private_fd = STDOUT_FILENO;

  else
    {
      const struct lsh_string *public;
      int public_fd;

      public = process_public(private, options);
      if (!public)
	return EXIT_FAILURE;

      private = process_private(private, options);
      if (!private)
	return EXIT_FAILURE;

      public_fd = open_file(options->public_file);
      if (public_fd < 0)
	return EXIT_FAILURE;

      if (!write_raw(public_fd, STRING_LD(public)))
	{
	  werror("Writing public key failed: %e.\n", errno);
	  return EXIT_FAILURE;
	}
      lsh_string_free(public);

      private_fd = open_file(options->private_file);
      if (private_fd < 0)
	return EXIT_FAILURE;

    }

  if (!write_raw(private_fd, STRING_LD(private)))
    {
      werror("Writing private key failed: %e.\n", errno);
      return EXIT_FAILURE;
    }

  lsh_string_free(private);

  return EXIT_SUCCESS;
}
