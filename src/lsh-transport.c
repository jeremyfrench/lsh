/* lsh-transport.c
 *
 * Client program responsible for the transport protocol and
 * user authnetication.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2005, Niels Möller
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
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>

/* For struct spki_iterator */
#include "spki/parse.h"

#include "algorithms.h"
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "publickey_crypto.h"
#include "randomness.h"
#include "resource.h"
#include "service.h"
#include "spki.h"
#include "ssh.h"
#include "ssh_write.h"
#include "transport.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh-transport.c.x"

static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno, uint32_t length, const uint8_t *packet);

static void
lsh_transport_service_start_read(struct lsh_transport_connection *self);

static void
lsh_transport_service_stop_read(struct lsh_transport_connection *self);

static void
lsh_transport_service_start_write(struct lsh_transport_connection *self);

static void
lsh_transport_service_stop_write(struct lsh_transport_connection *self);

struct lsh_transport_lookup_verifier;

static struct lsh_transport_lookup_verifier *
make_lsh_transport_lookup_verifier(struct lsh_transport_config *config);

/* GABA:
   (class
     (name lsh_transport_config)
     (super transport_context)
     (vars       
       (tty object interact)

       (sloppy . int)
       (capture_file . "const char *")
       (capture_fd . int)

       (signature_algorithms object alist)
       (host_acls . "const char *")
       (host_db object lsh_transport_lookup_verifier)

       (home . "const char *")       
       (port . "const char *")
       (target . "const char *")

       (local_user . "char *")
       (user . "char *")
       (identity . "char *")

       (service . "const char *")))
*/

static struct lsh_transport_config *
make_lsh_transport_config(oop_source *oop)
{
  NEW(lsh_transport_config, self);
  self->super.is_server = 0;
  self->super.oop = oop;

  self->home = getenv(ENV_HOME);
  if (!self->home)
    {
      werror("No home directory. Please set HOME in the environment.");
      return NULL;
    }
  
  self->super.random = make_user_random(self->home);
  if (!self->super.random)
    {
      werror("No randomness generator available.\n");
      return NULL;
    }
  
  self->super.algorithms = all_symmetric_algorithms();
  self->signature_algorithms = all_signature_algorithms(self->super.random);

  self->tty = make_unix_interact();
  self->host_db = make_lsh_transport_lookup_verifier(self);

  ALIST_SET(self->super.algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_client_dh_exchange(make_dh_group14(&crypto_sha1_algorithm),
				     &self->host_db->super)->super);
  self->super.kexinit
    = make_simple_kexinit(make_int_list(1, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1, -1),
			  default_hostkey_algorithms(),
			  default_crypto_algorithms(self->super.algorithms),
			  default_mac_algorithms(self->super.algorithms),
			  default_compression_algorithms(self->super.algorithms),
			  make_int_list(0, -1));
  self->sloppy = 0;
  self->capture_file = NULL;
  self->capture_fd = -1;
  self->host_acls = NULL;

  self->port = "22";
  self->target = NULL;

  USER_NAME_FROM_ENV(self->user);
  self->local_user = self->user;
  self->identity = NULL;

  self->service = "ssh-connection";
  
  return self;
}

/* GABA:
   (class
     (name lsh_transport_connection)
     (super transport_connection)
     (vars
       (service_reader object service_read_state)
       (service_read_active . int)
       (service_writer object ssh_write_state)
       (service_write_active . int)))     
*/

static void
kill_lsh_transport_connection(struct resource *s UNUSED)
{
  exit(EXIT_SUCCESS);
}

static int
lsh_transport_event_handler(struct transport_connection *connection,
			    enum transport_event event)
{
  CAST(lsh_transport_connection, self, connection);
  switch (event)
    {
    case TRANSPORT_EVENT_START_APPLICATION:
      lsh_transport_service_start_read(self);
      break;
    case TRANSPORT_EVENT_STOP_APPLICATION:
      lsh_transport_service_stop_read(self);
      break;
    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      connection->packet_handler = lsh_transport_packet_handler;
      break;
    case TRANSPORT_EVENT_CLOSE:
      /* FIXME: Should allow service buffer to drain. */
      break;
    case TRANSPORT_EVENT_PUSH:
      {
	enum ssh_write_status status;

	status = ssh_write_flush(self->service_writer, STDOUT_FILENO);

	switch(status)
	  {
	  case SSH_WRITE_IO_ERROR:
	    transport_disconnect(&self->super,
				 SSH_DISCONNECT_BY_APPLICATION,
				 "Connection to service layer failed.");
	    break;
	  case SSH_WRITE_OVERFLOW:
	    werror("Overflow from ssh_write_flush! Should not happen.\n");
	    transport_disconnect(&self->super,
				 SSH_DISCONNECT_BY_APPLICATION,
				 "Service layer not responsive.");
	    break;
	  case SSH_WRITE_PENDING:
	    lsh_transport_service_start_write(self);
      
	  case SSH_WRITE_COMPLETE:
	    lsh_transport_service_stop_write(self);
	    break;
	  }
	}
    }
  return 0;
}

static struct lsh_transport_connection *
make_lsh_transport_connection(struct lsh_transport_config *config, int fd)
{
  NEW(lsh_transport_connection, self);
  init_transport_connection(&self->super, kill_lsh_transport_connection,
			    &config->super, fd, fd,
			    lsh_transport_event_handler);
  self->service_reader = make_service_read_state();
  self->service_read_active = 0;
  self->service_writer = make_ssh_write_state(3 * SSH_MAX_PACKET, 1000);
  self->service_write_active = 0;

  return self;
}


static void
lsh_transport_line_handler(struct transport_connection *connection,
			   uint32_t length, const uint8_t *line)
{
  if (length < 4 || 0 != memcmp(line, "SSH-", 4))
    {
      /* A banner line */
      werror("%ps\n", length, line);
      return;
    }
  verbose("Server version string: %ps\n", length, line);

  /* Line must start with "SSH-2.0-". */
  if (length < 8 || 0 != memcmp(line, "SSH-2.0-", 4))
    {
      transport_disconnect(connection, 0, "Bad version string.");
      return;
    }
  
  connection->kex.version[1] = ssh_format("%ls", length, line);
  connection->line_handler = NULL;
}

/* Communication with service layer */

static void *
oop_read_service(oop_source *source UNUSED,
		 int fd UNUSED, oop_event event UNUSED, void *state UNUSED)
{
  return OOP_HALT;
}

static void
lsh_transport_service_start_read(struct lsh_transport_connection *self UNUSED)
{
}

static void
lsh_transport_service_stop_read(struct lsh_transport_connection *self UNUSED)
{
}

static void *
oop_write_service(oop_source *source UNUSED,
		  int fd UNUSED, oop_event event UNUSED, void *state UNUSED)
{
  return OOP_HALT;
}

static void
lsh_transport_service_start_write(struct lsh_transport_connection *self UNUSED)
{
}

static void
lsh_transport_service_stop_write(struct lsh_transport_connection *self UNUSED)
{
}

/* Handles decrypted packets. The various handler functions called
   from here should *not* free the packet. FIXME: Better to change
   this? */
static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno UNUSED, uint32_t length, const uint8_t *packet)
{
  CAST(lsh_transport_connection, self, connection);
  
  uint8_t msg;
  
  werror("Received packet: %xs\n", length, packet);
  assert(length > 0);

  msg = packet[0];
  /* XXX */

  return 1;
}

static int
lsh_connect(struct lsh_transport_config *config)
{
  struct lsh_transport_connection *connection;

  struct addrinfo hints;
  struct addrinfo *list;
  struct addrinfo *p;
  int err;
  int s = -1;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  err = getaddrinfo(config->target, config->port, &hints, &list);
  if (err)
    {
      werror("Could not resolv address `%z', port %z: %z\n",
	     config->target, config->port, gai_strerror(err));
      return 0;
    }

  for (p = list; p; p = p->ai_next)
    {
      s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (s < 0)
	continue;

      if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
	break;

      if (p->ai_next)
	werror("Connection failed, trying next address.\n");
      else
	werror("Connection failed.\n");
      close(s);
      s = -1;
    }
  
  freeaddrinfo(list);

  if (s < 0)
    return 0;
  
  /* We keep the socket in blocking mode */
  connection = make_lsh_transport_connection(config, s);
  gc_global(&connection->super.super);

  transport_handshake(&connection->super,
		      make_string("SSH-2.0-lsh-transport"),
		      lsh_transport_line_handler);

  return 1;
}

/* Maps a host key to a (trusted) verifier object. */

/* GABA:
   (class
     (name lsh_transport_lookup_verifier)
     (super lookup_verifier)
     (vars
       (config object lsh_transport_config)
       (db object spki_context)
       (access string)
       ; For fingerprinting
       (hash const object hash_algorithm)))
*/

static struct verifier *
lsh_transport_lookup_verifier(struct lookup_verifier *s,
			      int hostkey_algorithm,
			      uint32_t key_length, const uint8_t *key)
{
  CAST(lsh_transport_lookup_verifier, self, s);
  struct spki_principal *subject;

  switch (hostkey_algorithm)
    {
    case ATOM_SSH_DSS:
      {	
	struct lsh_string *spki_key;
	struct verifier *v = make_ssh_dss_verifier(key_length, key);

	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-dss key.\n");
	    return NULL;
	  }

	/* FIXME: It seems like a waste to pick apart the sexp again */
	spki_key = PUBLIC_SPKI_KEY(v, 0);

	subject = spki_lookup(self->db, STRING_LD(spki_key), v);
	assert(subject);
	assert(subject->verifier);

	lsh_string_free(spki_key);
	break;
      }
    case ATOM_SSH_RSA:
      {
	struct lsh_string *spki_key;
	struct verifier *v = make_ssh_rsa_verifier(key_length, key);

	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-rsa key.\n");
	    return NULL;
	  }

	/* FIXME: It seems like a waste to pick apart the sexp again */
	spki_key = PUBLIC_SPKI_KEY(v, 0);
	subject = spki_lookup(self->db, STRING_LD(spki_key), v);
	assert(subject);
	assert(subject->verifier);

	lsh_string_free(spki_key);
	break;
      }
      
      /* It doesn't matter here which flavour of SPKI is used. */
    case ATOM_SPKI_SIGN_RSA:
    case ATOM_SPKI_SIGN_DSS:
      {
	subject = spki_lookup(self->db, key_length, key, NULL);
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

  if (spki_authorize(self->db, subject, time(NULL), self->access))
    {
      verbose("SPKI host authorization successful!\n");
    }
  else
    {
      struct lsh_string *acl;
      struct spki_iterator i;
      
      verbose("SPKI authorization failed.\n");
      if (!self->config->sloppy)
	{
	  werror("Server's hostkey is not trusted. Disconnecting.\n");
	  return NULL;
	}
      
      /* Ok, let's see if we want to use this untrusted key. */
      if (!quiet_flag)
	{
	  /* Display fingerprint */
	  /* FIXME: Rewrite to use libspki subject */
#if 0
	  struct lsh_string *spki_fingerprint = 
	    hash_string(self->hash, subject->key, 0);
#endif
	  
	  struct lsh_string *fingerprint = 
	    lsh_string_colonize( 
				ssh_format( "%lfxS", 
					    hash_string_l(&crypto_md5_algorithm,
							  key_length, key)
					    ), 
				2, 
				1  
				);

	  struct lsh_string *babble = 
	    lsh_string_bubblebabble( 
				    hash_string_l(&crypto_sha1_algorithm,
						  key_length, key),
				    1 
				    );
	  
	  if (!INTERACT_YES_OR_NO
	      (self->config->tty,
	       ssh_format("Received unauthenticated key for host %lz\n"
			  "Key details:\n"
			  "Bubble Babble: %lfS\n"
			  "Fingerprint:   %lfS\n"
			  "Do you trust this key? (y/n) ",
			  self->config->target, babble, fingerprint), 0, 1))
	    return NULL;
	}

      acl = lsh_string_format_sexp(0, "(acl(entry(subject%l)%l))",
				   subject->key_length, subject->key,
				   STRING_LD(self->access));
      
      /* FIXME: Seems awkward to pick the acl apart again. */
      if (!spki_iterator_first(&i, STRING_LD(acl)))
	fatal("Internal error.\n");
      
      /* Remember this key. We don't want to ask again for key re-exchange */
      spki_add_acl(self->db, &i);

      /* Write an ACL to disk. */
      if (self->config->capture_fd > 0)
	{
	  int fd = open(self->config->capture_file, O_RDWR | O_APPEND | O_CREAT, 0666);

	  if (fd < 0)
	    werror("Opening `%z' for writing failed: %e\n",
		   self->config->capture_file, errno);
	  else
	    {
	      struct lsh_string *entry
		= ssh_format("\n; ACL for host %lz\n"
			     "%lfS\n",
			     self->config->target,
			     lsh_string_format_sexp(1, "%l", STRING_LD(acl)));
	      if (!write_raw(fd, STRING_LD(entry)))
		werror("Writing acl entry failed: %e\n", errno);

	      lsh_string_free(entry);
	      close(fd);
	    }
	}
      lsh_string_free(acl);
    }
  
  return subject->verifier;
}

static struct lsh_transport_lookup_verifier *
make_lsh_transport_lookup_verifier(struct lsh_transport_config *config)
{
  NEW(lsh_transport_lookup_verifier, self);
  self->super.lookup = lsh_transport_lookup_verifier;
  self->config = config;
  self->db = NULL;
  self->access = NULL;
  self->hash = &crypto_sha1_algorithm;
  
  return self;
}

/* Initialize the spki database and the access tag. Called after
   options parsing. */
static void
read_host_acls(struct lsh_transport_lookup_verifier *self)
{
  struct lsh_string *contents;
  int fd;
  struct spki_iterator i;
  const char *sexp_conv;
  const char *args[] = { "sexp-conv", "-s", "canonical", NULL };

  assert(self->config->target);
  
  self->access = make_ssh_hostkey_tag(self->config->target);
  self->db = make_spki_context(self->config->signature_algorithms);
  
  if (self->config->host_acls)
    {
      fd = open(self->config->host_acls, O_RDONLY);
      if (fd < 0)
	{
	  werror("Failed to open `%z' for reading: %e\n",
		 self->config->host_acls, errno);
	  return;
	}
    }
  else
    {
      struct lsh_string *tmp = ssh_format("%lz/.lsh/host-acls", self->config->home);
      fd = open(lsh_get_cstring(tmp), O_RDONLY);
      
      if (fd < 0)
	{
	  struct stat sbuf;
	  struct lsh_string *known_hosts;

	  werror("Failed to open `%S' for reading: %e\n", tmp, errno);
	  known_hosts = ssh_format("%lz/.lsh/known_hosts", self->config->home);

	  if (stat(lsh_get_cstring(known_hosts), &sbuf) == 0)
	    {
	      werror("You have an old known-hosts file `%S'.\n"
		     "To work with lsh-2.0, run the lsh-upgrade script,\n"
		     "which will convert that to a new host-acls file.\n",
		     tmp);
	    }
	  lsh_string_free(known_hosts);
	  lsh_string_free(tmp);
	  return;
	}
      lsh_string_free(tmp);
    }

  sexp_conv = getenv(ENV_SEXP_CONV);
  if (!sexp_conv)
    sexp_conv = PATH_SEXP_CONV;
  
  contents = lsh_popen_read(sexp_conv, args, fd, 5000);
  
  if (!contents)
    {
      werror("Failed to read host-acls file: %e\n", errno);
      close(fd);
      return;
    }

  close(fd);

  if (!spki_iterator_first(&i, STRING_LD(contents)))
    werror("read_known_hosts: S-expression syntax error.\n");
    
  else
    while (i.type != SPKI_TYPE_END_OF_EXPR)
      {
	if (!spki_add_acl(self->db, &i))
	  {
	    werror("read_known_hosts: Invalid ACL.\n");
	    break;
	  }
      }
  lsh_string_free(contents);
}

/* Option parsing */

const char *argp_program_version
= "lsh-transport (lsh-" VERSION "), secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

/* Transport options */
#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204
#define OPT_HOST_DB 0x205

/* Userauth options */
#define OPT_USERAUTH 0x210
#define OPT_PUBLICKEY 0x211

/* FIXME: Enable/disable password, kbdinteract, etc */

/* Service options */
#define OPT_SERVICE 0x220

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  /* Connection */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },

  /* Host authentication */
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/host-acls", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new untrusted hostkey is received, append an ACL expressing trust in the key. "
    "The default is ~/.lsh/captured_keys.", 0 },
  
  /* User authentication */
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "service" , OPT_SERVICE, "Name", 0, "Service to request. Default is `ssh-connection'.", 0},
  
  { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_transport_config, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;

    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;

    case ARGP_KEY_ARG:
      if (!state->arg_num)
	self->target = arg;
      
      else
	return ARGP_ERR_UNKNOWN;

      break;
      
    case ARGP_KEY_END:
      read_host_acls(self->host_db);

      if (self->capture_file)
	{
	  self->capture_fd = open(self->capture_file,
				  O_RDWR | O_APPEND | O_CREAT, 0600);
	  if (self->capture_fd < 0)
	    werror("Opening `%z' for writing failed: %e\n",
		   self->capture_file, errno);
	}
      else if (self->sloppy)
	{
	  struct lsh_string *s = ssh_format("%lz/.lsh/captured-keys", self->home);
	  self->capture_fd = open(lsh_get_cstring(s),
				  O_RDWR | O_APPEND | O_CREAT, 0600);
	  if (self->capture_fd < 0)
	    werror("Opening `%S' for writing failed: %e\n",
		   s, errno);
	  
	  lsh_string_free(s);
	}
      break;
      
    case 'p':
      self->port = arg;
      break;

    case OPT_HOST_DB:
      self->host_acls = arg;
      break;
      
    case OPT_SLOPPY:
      self->sloppy = 1;
      break;

    case OPT_STRICT:
      self->sloppy = 0;
      break;

    case OPT_CAPTURE:
      self->capture_file = arg;
      break;

    case 'i':
      self->identity = arg;
      break;

    case OPT_SERVICE:
      self->service = arg;
      break;
    }
  return 0;
}

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ main_options, main_argp_parser,
  "host",
  "Creates a secure shell connection to a remote host\v"
  "Uses secure shell transport and userauth protocols to "
  "talk to the remote host. On success, reads cleartext"
  "ssh messages on stdin writes cleartext messages to stdout.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{
  struct lsh_transport_config *config;
  struct oop_source *source = io_init();
  
  config = make_lsh_transport_config(source);
  if (!config)
    return EXIT_FAILURE;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, config);

  if (!lsh_connect(config))
    return EXIT_FAILURE;

  io_run();
  io_final();

  return EXIT_SUCCESS;
}
