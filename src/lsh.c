/* lsh.c
 *
 * client main program
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000 Niels Möller
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
#include "client_userauth.h"
#include "compress.h"
#include "connection_commands.h"
#include "crypto.h"
#include "dsa.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "io_commands.h"
#include "gateway.h"
#include "gateway_commands.h"
#include "handshake.h"
#include "lookup_verifier.h"
#include "publickey_crypto.h"
#include "randomness.h"
#include "sexp.h"
#include "spki.h"
#include "srp.h" 
#include "ssh.h"
#include "tcpforward_commands.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lsh_argp.h"

/* Forward declarations */
struct command_2 lsh_verifier_command;
#define OPTIONS2VERIFIER (&lsh_verifier_command.super.super)

struct command_2 lsh_login_command;
#define LSH_LOGIN (&lsh_login_command.super.super)

struct command options2service;
#define OPTIONS2SERVICE (&options2service.super)

static struct command options2identities;
#define OPTIONS2IDENTITIES (&options2identities.super)

static struct request_service request_userauth_service =
STATIC_REQUEST_SERVICE(ATOM_SSH_USERAUTH);
#define REQUEST_USERAUTH_SERVICE (&request_userauth_service.super.super)


#include "lsh.c.x"

/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel
 *
 * NOTE: Large windows seem to trig a bug in sshd2. */
#define WINDOW_SIZE 10000

/* GABA:
   (class
     (name lsh_options)
     (super client_options)
     (vars
       (algorithms object algorithms_options)

       (signature_algorithms object alist)
       (home . "const char *")
       
       (identity . "char *")
       (with_publickey . int)

       (with_srp_keyexchange . int)
       (with_dh_keyexchange . int)

       ; Command to invoke to start ssh-connection service)
       (service object command)
       
       ;; (kexinit object make_kexinit)
       (kex_algorithms object int_list)
       
       (sloppy . int)
       (capture . "const char *")
       (capture_file object abstract_write)

       (known_hosts . "const char *")
       
       (start_gateway . int)))
*/


static struct lsh_options *
make_options(struct exception_handler *handler,
	     int *exit_code)
{
  NEW(lsh_options, self);
  const char *home = getenv("HOME");
  struct randomness *r = make_user_random(home);

  if (!r)
    {
      werror("Failed to initialize randomness generator.\n");
      return NULL;
    }
  
  init_client_options(&self->super, 
		      r,
		      handler, exit_code);

  self->algorithms
    = make_algorithms_options(all_symmetric_algorithms());

  self->home = home;
  
  self->signature_algorithms = all_signature_algorithms(r);

  self->sloppy = 0;
  self->capture = NULL;
  self->capture_file = NULL;

  self->known_hosts = NULL;
  
  self->start_gateway = 0;

  self->with_publickey = 1;

  self->with_srp_keyexchange = 0;

  /* By default, enable only one of dh and srp. */
  self->with_dh_keyexchange = -1;
  
  self->kex_algorithms = NULL;
  
  return self;
}


/* Request ssh-userauth or ssh-connection service, as appropriate,
 * and pass the options as a first argument. */
DEFINE_COMMAND(options2service)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(lsh_options, options, a);
  COMMAND_RETURN(c, options->service);
}

/* Open hostkey database. By default, "~/.lsh/known_hosts". */

static struct spki_context *
read_known_hosts(struct lsh_options *options)
{
  struct lsh_string *tmp = NULL;
  struct lsh_string *contents;
  const char *s = NULL;
  int fd;
  struct simple_buffer buffer;
  struct spki_context *context;

  context = make_spki_context(options->signature_algorithms);
  
  if (options->known_hosts)
    s = options->known_hosts;
  else
    {
      tmp = ssh_format("%lz/.lsh/known_hosts", options->home);
      s = lsh_get_cstring(tmp);
    }

  fd = open(s, O_RDONLY);
  if (fd < 0)
    {
      lsh_string_free(tmp);
      werror("Failed to open `%z' for reading: %z\n",
             s, STRERROR(errno));
      return context;
    }

  lsh_string_free(tmp);

  contents = io_read_file_raw(fd, 5000);
  
  if (!contents)
  {
    werror("Failed to read known_hosts file: %z\n",
           STRERROR(errno));
    close(fd);
    return context;
  }

  close(fd);

  simple_buffer_init(&buffer, contents->length, contents->data);
  while (!parse_eod(&buffer))
    {
      struct sexp *expr = sexp_parse(SEXP_TRANSPORT, &buffer);

      if (!expr)
        {
          werror("read_known_hosts: S-expression syntax error.\n");
          break;
        }
      if (!spki_add_acl(context, expr))
        {
          werror("read_known_hosts: Invalid ACL.\n");
          break;
        }
    }
  lsh_string_free(contents);
  return context;
}

/* For now, supports only a single key */
static struct object_list *
read_user_keys(struct lsh_options *options)
{
  struct lsh_string *tmp = NULL;
  struct lsh_string *contents;
  const char *name = NULL;
  struct sexp *expr;
  int fd;
  int algorithm_name;
  
  struct signer *s;
  struct verifier *v;
  struct lsh_string *spki_public;

  trace("read-user_keys\n");
  
  if (!options->with_publickey)
    return make_object_list(0, -1);

  if (options->identity)
    name = options->identity;
  else 
    {
      tmp = ssh_format("%lz/.lsh/identity", options->home);
      name = lsh_get_cstring(tmp);
    }

  fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      werror("Failed to open `%z' for reading: %z\n",
             name, STRERROR(errno));
      lsh_string_free(tmp);

      return make_object_list(0, -1);
    }

  lsh_string_free(tmp);

  contents = io_read_file_raw(fd, 2000);

  if (!contents)
    {
      werror("Failed to read private key file: %z\n",
             STRERROR(errno));
      close(fd);

      return make_object_list(0, -1);
    }

  close(fd);

  expr = string_to_sexp(SEXP_TRANSPORT, contents, 1);

  if (!expr)
    {
      werror("S-expression syntax error in private key.\n");
      return make_object_list(0, -1);
    }

  if (options->super.tty)
    {
      struct alist *mac = make_alist(0, -1);
      struct alist *crypto = make_alist(0, -1);

      alist_select_l(mac, options->algorithms->algorithms,
		     2, ATOM_HMAC_SHA1, ATOM_HMAC_MD5, -1);
      alist_select_l(crypto, options->algorithms->algorithms,
		     3, ATOM_3DES_CBC, ATOM_BLOWFISH_CBC,
		     ATOM_RIJNDAEL_CBC_LOCAL, -1);
      
      expr = spki_pkcs5_decrypt(mac, crypto,
                                options->super.tty,
                                expr);
      if (!expr)
        {
          werror("Decrypting private key failed.\n");
          return make_object_list(0, -1);
        }
    }
  
  s = spki_sexp_to_signer(options->signature_algorithms, expr,
                          &algorithm_name);
  if (!s)
    {
      werror("Invalid private key.\n");
      return make_object_list(0, -1);
    }
  
  v = SIGNER_GET_VERIFIER(s);
  assert(v);
  
  spki_public = sexp_format(spki_make_public_key(v),
			    SEXP_CANONICAL, 0);

  /* Test key here? */  
  switch (algorithm_name)
    {	  
    case ATOM_DSA:
      return make_object_list(2,
                              make_keypair(ATOM_SSH_DSS,
                                           PUBLIC_KEY(v),
                                           s),
                              make_keypair(ATOM_SPKI_SIGN_DSS,
                                           spki_public, s),
                              -1);
      break;

    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      return make_object_list(2, 
                              make_keypair(ATOM_SSH_RSA,
                                           PUBLIC_KEY(v),
                                           s),
                              make_keypair(ATOM_SPKI_SIGN_RSA,
                                           spki_public, s),
                              -1);

    case ATOM_RSA_PKCS1_MD5:
      return make_object_list(1,
                              make_keypair(ATOM_SPKI_SIGN_RSA,
                                           spki_public, s),
                              -1);

    default:
      fatal("Internal error!\n");
    }
}

/* FIXME: Call read_user_key directly from main instead. */

/* Read user's private keys. By default, "~/.lsh/identity". */
static void
do_options2identities(struct command *ignored UNUSED,
		      struct lsh_object *a,
		      struct command_continuation *c,
		      struct exception_handler *e UNUSED)
{
  CAST(lsh_options, options, a);

  COMMAND_RETURN(c, read_user_keys(options));
}

static struct command options2identities =
STATIC_COMMAND(do_options2identities);


/* Maps a host key to a (trusted) verifier object. */

/* GABA:
   (class
     (name lsh_host_db)
     (super lookup_verifier)
     (vars
       (db object spki_context)
       (tty object interact)
       (access object sexp)
       (host object address_info)
       ; Allow unauthorized keys
       (sloppy . int)
       ; If non-null, append an ACL for the received key to this file.
       (file object abstract_write)
       ; For fingerprinting
       (hash object hash_algorithm)))
*/

static struct verifier *
do_lsh_lookup(struct lookup_verifier *c,
	      int method,
	      struct lsh_user *keyholder UNUSED,
	      struct lsh_string *key)
{
  CAST(lsh_host_db, self, c);
  struct spki_subject *subject;

  switch (method)
    {
    case ATOM_SSH_DSS:
      {
	struct verifier *v = make_ssh_dss_verifier(key->length, key->data);
	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-dss key.\n");
	    return NULL;
	  }
	subject = SPKI_LOOKUP(self->db,
			      spki_make_public_key(v),
			      v);
	assert(subject);
	assert(subject->verifier);
	break;
      }
    case ATOM_SSH_RSA:
      {
	struct verifier *v = make_ssh_rsa_verifier(key->length, key->data);
	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-rsa key.\n");
	    return NULL;
	  }
	subject = SPKI_LOOKUP(self->db,
			      spki_make_public_key(v),
			      v);
	assert(subject);
	assert(subject->verifier);
	break;
      }
      
#if 0
    case ATOM_RSA_PKCS1_SHA1_LOCAL:
      {
	struct rsa_verifier *v = make_ssh_rsa_verifier(key->length, key->data);
	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-rsa key.\n");
	    return NULL;
	  }
	subject = SPKI_LOOKUP(self->db,
			      rsa_to_spki_public_key(&v->public),
			      &v->super);
	assert(subject);
	assert(subject->verifier);
	break;
      }
      
    case ATOM_SPKI:
#endif
      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:
      {
	struct sexp *e = string_to_sexp(SEXP_CANONICAL, key, 0);
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
      verbose("SPKI host authorization successful!\n");
    }
  else
    {
      struct sexp *acl;
      
      verbose("SPKI authorization failed.\n");
      if (!self->sloppy)
	{
	  werror("Server's hostkey is not trusted. Disconnecting.\n");
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
			  
	  if (!INTERACT_YES_OR_NO
	      (self->tty,
	       ssh_format("Received unauthenticated key for host %lS\n"
			  "Fingerprint: %lfxS\n"
			  "Do you trust this key? (y/n) ",
			  self->host->ip, fingerprint), 0, 1))
	    return NULL;
	}

      acl = sexp_l(2, sexp_a(ATOM_ACL),
		   sexp_l(3, sexp_a(ATOM_ENTRY),
			  subject->key,
			  sexp_l(2, sexp_a(ATOM_TAG),
				 self->access,
				 -1),
			  -1),
		   -1);

      /* Remember this key. We don't want to ask again for key re-exchange */
      spki_add_acl(self->db, acl);
      
      /* Write an ACL to disk. */
      if (self->file)
	{
	  A_WRITE(self->file, ssh_format("\n; ACL for host %lS\n", self->host->ip));
	  A_WRITE(self->file,
		  sexp_format(acl, SEXP_TRANSPORT, 0));
	  A_WRITE(self->file, ssh_format("\n"));
	}
    }
  
  return subject->verifier;
}

static struct lookup_verifier *
make_lsh_host_db(struct spki_context *db,
		 struct interact *tty,
		 struct address_info *host,
		 int sloppy,
		 struct abstract_write *file)
{
  NEW(lsh_host_db, res);

  res->super.lookup = do_lsh_lookup;
  res->db = db;
  res->tty = tty;
  res->access = make_ssh_hostkey_tag(host);
  res->host = host;
  res->sloppy = sloppy;
  res->file = file;
  res->hash = &sha1_algorithm;

  return &res->super;
}

/* Takes options and an spki_context as argument and returns a
 * lookup_verifier */

DEFINE_COMMAND2(lsh_verifier_command)
     (struct command_2 *s UNUSED,
      struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(lsh_options, options, a1);
  CAST_SUBTYPE(spki_context, db, a2);
  COMMAND_RETURN(c, make_lsh_host_db(db,
				     options->super.tty,
				     options->super.remote,
				     options->sloppy,
				     options->capture_file));
}


/* (login options public-keys connection) */
DEFINE_COMMAND2(lsh_login_command)
     (struct command_2 *s UNUSED,
      struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(lsh_options, options, a1);
  CAST_SUBTYPE(object_list, keys, a2);

  struct client_userauth_method *password
    = make_client_password_auth(options->super.tty);

  /* FIXME: Perhaps we should try "none" only when using SRP. */
  struct client_userauth_method *none
    = make_client_none_auth();
  
  COMMAND_RETURN(c,
		 make_client_userauth
		 (ssh_format("%lz", options->super.user),
		  ATOM_SSH_CONNECTION,
		  (LIST_LENGTH(keys)
		   ? make_object_list
		   (3,
                    none,
		    make_client_publickey_auth(keys),
		    password,
		    -1)
		   : make_object_list(2, none, password, -1))));
}


/* NOTE: options2identities can block for reading, so it must not be
 * invoked directly. */

/* Requests the ssh-userauth service, log in, and request connection
 * service. */
/* GABA:
   (expr
     (name make_lsh_userauth)
     (params
       (options object lsh_options))
     (expr
       (lambda (connection)
         (lsh_login options
	   
	   ; The prog1 delay is needed because options2identities
	   ; may not return immediately.
	   (options2identities (prog1 options connection))

	   ; Request the userauth service
	   (request_userauth_service connection))))) */

/* GABA:
   (expr
     (name make_lsh_connect)
     (params
       (handshake object handshake_info)
       (init object make_kexinit)
       (db object lookup_verifier))
     (expr (lambda (options)
               ; What to do with the service
	       ((progn (options2actions options))
	         ; Initialize service
		 (init_connection_service
		   ; Either requests ssh-connection service,
		   ; or requests and uses the ssh-userauth service.
		   (options2service options
		     ; Start the ssh transport protocol
	             (connection_handshake
		       handshake init
		       db
 		       ; Connect using tcp
		       (connect_simple (options2remote options)))))))))
*/


/* Option parsing */

const char *argp_program_version
= "lsh-" VERSION ", secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

#define OPT_PUBLICKEY 0x201

#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204

#define OPT_HOST_DB 0x205

#define OPT_DH 0x206
#define OPT_SRP 0x207

#define OPT_STDIN 0x210
#define OPT_STDOUT 0x211
#define OPT_STDERR 0x212

#define OPT_FORK_STDIO 0x213

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "publickey", OPT_PUBLICKEY, NULL, 0,
    "Try publickey user authentication (default).", 0 },
  { "no-publickey", OPT_PUBLICKEY | ARG_NOT, NULL, 0,
    "Don't try publickey user authentication.", 0 },
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/known_hosts", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new hostkey is received, append an ACL expressing trust in the key. "
    "In sloppy mode, the default is ~/.lsh/captured_keys.", 0 },
#if WITH_SRP
  { "srp-keyexchange", OPT_SRP, NULL, 0, "Enable experimental SRP support.", 0 },
  { "no-srp-keyexchange", OPT_SRP | ARG_NOT, NULL, 0, "Disable experimental SRP support (default).", 0 },
#endif /* WITH_SRP */

  { "dh-keyexchange", OPT_DH, NULL, 0,
    "Enable DH support (default, unless SRP is being used).", 0 },

  { "no-dh-keyexchange", OPT_DH | ARG_NOT, NULL, 0, "Disable DH support.", 0 },
  
  /* Actions */
  { "forward-remote-port", 'R', "remote-port:target-host:target-port",
    0, "", CLIENT_ARGP_ACTION_GROUP },
  { "gateway", 'G', NULL, 0, "Setup a local gateway", 0 },

  /* FIXME: Perhaps this should be moved from lsh.c to client.c? It
   * doesn't work with lshg. Or perhaps that can be fixed?
   * About the same problem applies to -R. */
  
  { "x11-forward", 'x', NULL, 0, "Enable X11 forwarding.", CLIENT_ARGP_MODIFIER_GROUP },
  { "no-x11-forward", 'x' | ARG_NOT, NULL, 0,
    "Disable X11 forwarding (default).", 0 },
  
  { NULL, 0, NULL, 0, NULL, 0 }
};


static const struct argp_child
main_argp_children[] =
{
  { &client_argp, 0, "", 0 },
  { &algorithms_argp, 0, "", 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

#define CASE_ARG(opt, attr, none)		\
  case opt:					\
    if (self->super.not)			\
      {						\
        self->super.not = 0;			\
						\
      case opt | ARG_NOT:			\
        self->attr = none;			\
        break;					\
      }						\
      						\
    self->attr = arg;				\
    break

#define CASE_FLAG(opt, flag)			\
  case opt:					\
    if (self->super.not)			\
      {						\
        self->super.not = 0;			\
						\
      case opt | ARG_NOT:			\
        self->flag = 0;				\
        break;					\
      }						\
      						\
    self->flag = 1;				\
    break

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
      state->child_inputs[1] = self->algorithms;
      state->child_inputs[2] = NULL;
      break;
      
    case ARGP_KEY_END:
      if (!self->home)
	{
	  argp_error(state, "No home directory. Please set HOME in the environment.");
	  break;
	}

      if (self->with_dh_keyexchange < 0)
	self->with_dh_keyexchange = !self->with_srp_keyexchange;
      
      if (self->with_dh_keyexchange || self->with_srp_keyexchange)
	{
	  int i = 0;
	  self->kex_algorithms 
	    = alloc_int_list(self->with_dh_keyexchange + self->with_srp_keyexchange);
	    
#if WITH_SRP	    
	  if (self->with_srp_keyexchange)
	    {
	      LIST(self->kex_algorithms)[i++] = ATOM_SRP_RING1_SHA1_LOCAL;
	      ALIST_SET(self->algorithms->algorithms,
			ATOM_SRP_RING1_SHA1_LOCAL,
			&make_srp_client(make_srp1(self->super.random),
					 self->super.tty,
					 ssh_format("%lz", self->super.user))
			->super);
	    }
#endif /* WITH_SRP */
	  if (self->with_dh_keyexchange)
	    {
	      LIST(self->kex_algorithms)[i++] = ATOM_DIFFIE_HELLMAN_GROUP1_SHA1;
	      ALIST_SET(self->algorithms->algorithms,
			ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
			&make_dh_client(make_dh1(self->super.random))
			->super);
	    }
	}
      else
	argp_error(state, "All keyexchange algorithms disabled.");

      {
        CAST_SUBTYPE(command, o, make_lsh_userauth(self));
        self->service = o;
      }
	
      {
	struct lsh_string *tmp = NULL;
	const char *s = NULL;
	  
	if (self->capture)
	  s = self->capture;
	else if (self->sloppy)
	  {
	    tmp = ssh_format("%lz/.lsh/captured_keys", self->home);
	    s = lsh_get_cstring(tmp);
	  }
	if (s)
	  {
	    struct lsh_fd *f
	      = io_write_file(s,
			      O_CREAT | O_APPEND | O_WRONLY,
			      0600, 500, NULL,
			      make_report_exception_handler
			      (make_report_exception_info(EXC_IO, EXC_IO,
							  "Writing new ACL: "),
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

      /* We can't add the gateway action immediately when the -G
       * option is encountered, as we need the name and port of the
       * remote machine (self->super.remote) first. */
      if (self->start_gateway)
	{
	  struct local_info *gateway;
	  if (!self->super.local_user)
	    {
	      argp_error(state, "You have to set LOGNAME in the environment, "
			 " if you want to use the gateway feature.");
	      break;
	    }
	  gateway = make_gateway_address(self->super.local_user,
					 self->super.user,
					 self->super.remote);

	  if (!gateway)
	    {
	      argp_error(state, "Local or remote user name, or the target host name, are too "
			 "strange for the gateway socket name construction.");
	      break;
	    }
	      
	  client_add_action(&self->super,
			    make_gateway_setup
			    (make_listen_local(gateway)));
	}

      if (object_queue_is_empty(&self->super.actions))
	{
	  argp_error(state, "No actions given.");
	  break;
	}

      break;
      
    case 'i':
      self->identity = arg;
      break;

    CASE_FLAG(OPT_PUBLICKEY, with_publickey);

    case OPT_HOST_DB:
      self->known_hosts = arg;
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

    CASE_FLAG(OPT_DH, with_dh_keyexchange);
    CASE_FLAG(OPT_SRP, with_srp_keyexchange);

    case 'R':
      {
	UINT32 listen_port;
	struct address_info *target;

	if (!client_parse_forward_arg(arg, &listen_port, &target))
	  argp_error(state, "Invalid forward specification '%s'.", arg);

	client_add_action(&self->super, make_forward_remote_port
			  (make_address_info((self->super.with_remote_peers
					      ? ssh_format("%lz", "0.0.0.0")
					      : ssh_format("%lz", "127.0.0.1")),
					     listen_port),
			   target));

	self->super.remote_forward = 1;
	break;
      }      
      
    CASE_FLAG('G', start_gateway);
    CASE_FLAG('x', super.with_x11);
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
      *self->status = EXIT_FAILURE;
      
      werror("%z, (errno = %i)\n", e->msg, exc->error);
    }
  else
    switch(e->type)
      {
      case EXC_RESOLVE:
      case EXC_USERAUTH:
      case EXC_SEXP_SYNTAX:
      case EXC_SPKI_TYPE:
      case EXC_GLOBAL_REQUEST:
      case EXC_CHANNEL_REQUEST:
      case EXC_CHANNEL_OPEN:

	werror("%z\n", e->msg);
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
  struct spki_context *spki;
  
  /* Default exit code if something goes wrong. */
  int lsh_exit_code = 17;

  struct exception_handler *handler
    = make_lsh_default_handler(&lsh_exit_code, &default_exception_handler,
			       HANDLER_CONTEXT);

  io_init();
  
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  options = make_options(handler, &lsh_exit_code);
  if (!options)
    return EXIT_FAILURE;
  
  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);

  spki = read_known_hosts(options);
  
  {
    struct lsh_object *o =
      make_lsh_connect(
	make_handshake_info(CONNECTION_CLIENT,
			    "lsh - a free ssh", NULL,
			    SSH_MAX_PACKET,
			    options->super.random,
			    options->algorithms->algorithms,
			    NULL),
	make_simple_kexinit(options->super.random,
			    options->kex_algorithms,
			    options->algorithms->hostkey_algorithms,
			    options->algorithms->crypto_algorithms,
			    options->algorithms->mac_algorithms,
			    options->algorithms->compression_algorithms,
			    make_int_list(0, -1)),
        make_lsh_host_db(spki,
                         options->super.tty,
                         options->super.remote,
                         options->sloppy,
                         options->capture_file));
    
    CAST_SUBTYPE(command, lsh_connect, o);

    COMMAND_CALL(lsh_connect, options, &discard_continuation,
		 handler);
	
  } 

#if 0
  /* All commands using stdout have dup:ed stdout by now. We close it,
   * because if stdout is a pipe, we want the reader to know whether
   * or not anybody is still using it. */
  close(STDOUT_FILENO);
  if (open("/dev/null", O_WRONLY) != STDOUT_FILENO)
    werror("Strange: Final redirect of stdout to /dev/null failed.\n");
#endif
  
  io_run();

  /* Close all files and other resources associated with the backend. */
  io_final();
  
  /* FIXME: Perhaps we have to reset the stdio file descriptors to
   * blocking mode? */
  return lsh_exit_code;
}
