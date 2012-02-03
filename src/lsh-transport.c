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
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>

#include "algorithms.h"
#include "charset.h"
#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "interact.h"
#include "io.h"
#include "keyexchange.h"
#include "lsh_string.h"
#include "parse.h"
#include "randomness.h"
#include "resource.h"
#include "service.h"
#include "spki.h"
#include "ssh.h"
#include "transport_forward.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

enum lsh_transport_state
{
  /* Initial handshake and key exchange */
  STATE_HANDSHAKE,
  /* We have sent our service request, waiting for reply. */
  STATE_SERVICE_REQUEST,
  /* We're trying to log in */
  STATE_USERAUTH,
  /* We're forwarding packets for the service */
  STATE_SERVICE_FORWARD,
};

#include "lsh-transport.c.x"

static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno, uint32_t length, const uint8_t *packet);

static int
try_password_auth(struct lsh_transport_connection *self);

static int
try_keyboard_interactive_auth(struct lsh_transport_connection *self);

static void
send_userauth_info_response(struct lsh_transport_connection *self,
			    struct simple_buffer *buffer);

static void
start_userauth(struct lsh_transport_connection *self);

static void
start_service(struct lsh_transport_connection *self);

struct lsh_transport_lookup_verifier;

static struct lsh_transport_lookup_verifier *
make_lsh_transport_lookup_verifier(struct lsh_transport_config *config);

/* GABA:
   (class
     (name lsh_transport_config)
     (super transport_context)
     (vars
       (algorithms object algorithms_options)
       (werror_config object werror_config)

       (kex_algorithms object int_list)

       (sloppy . int)
       (capture_file . "const char *")
       (capture_fd . int)

       (signature_algorithms object alist)
       (host_acls . "const char *")
       (host_db object lsh_transport_lookup_verifier)

       (home . "const char *")       
       (port . "const char *")
       (target . "const char *")

       (userauth . int)
       (user . "const char *")
       (identity . "const char *")
       (keypair object keypair)
       
       ; The service we ask for in the SERVICE_REQUEST
       (requested_service . "const char *")
       ; The service we ultimately want to start
       (service . "const char *")))
*/

static struct lsh_transport_config *
make_lsh_transport_config(void)
{
  NEW(lsh_transport_config, self);
  init_transport_context (&self->super, 0);

  self->home = getenv(ENV_HOME);
  if (!self->home)
    {
      werror("No home directory. Please set HOME in the environment.");
      return NULL;
    }

  self->algorithms = make_algorithms_options(self->super.algorithms);

  self->werror_config = make_werror_config();

  self->signature_algorithms = all_signature_algorithms();

  self->host_db = make_lsh_transport_lookup_verifier(self);

  ALIST_SET(self->super.algorithms, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
	    &make_client_dh_exchange(make_dh_group14(&nettle_sha1),
				     &self->host_db->super)->super);
  ALIST_SET(self->super.algorithms, ATOM_DIFFIE_HELLMAN_GROUP1_SHA1,
	    &make_client_dh_exchange(make_dh_group1(&nettle_sha1),
				     &self->host_db->super)->super);
  self->kex_algorithms =
    make_int_list(2, ATOM_DIFFIE_HELLMAN_GROUP14_SHA1,
		  ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, -1);
  
  self->sloppy = 0;
  self->capture_file = NULL;
  self->capture_fd = -1;
  self->host_acls = NULL;

  self->port = "22";
  self->target = NULL;

  self->userauth = 1;
  USER_NAME_FROM_ENV(self->user);
  self->identity = NULL;
  self->keypair = NULL;

  self->service = "ssh-connection";
  
  return self;
}

/* GABA:
   (class
     (name lsh_transport_connection)
     (super transport_forward)
     (vars
       (state . "enum lsh_transport_state")
       ;; For password authentication
       (config object lsh_transport_config)
       (tried_empty_password . unsigned)
       ;; For keyboard-interactive authentication
       (expect_info_request . int)))
*/

static void
kill_lsh_transport_connection(struct resource *s UNUSED)
{
  exit(EXIT_SUCCESS);
}

static void
lsh_transport_event_handler(struct transport_connection *connection,
			    enum transport_event event)
{
  CAST(lsh_transport_connection, self, connection);
  CAST(lsh_transport_config, config, connection->ctx);

  switch (event)
    {
    case TRANSPORT_EVENT_START_APPLICATION:
    case TRANSPORT_EVENT_STOP_APPLICATION:
    case TRANSPORT_EVENT_CLOSE:
    case TRANSPORT_EVENT_PUSH:
      /* Do nothing */
      break;

    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      assert(self->state == STATE_HANDSHAKE);

      transport_send_packet(
	connection, TRANSPORT_WRITE_FLAG_PUSH,
	ssh_format("%c%z", SSH_MSG_SERVICE_REQUEST,
		   config->requested_service));

      self->state = STATE_SERVICE_REQUEST;
      connection->packet_handler = lsh_transport_packet_handler;
      break;
    }
 }

static void
lsh_transport_service_packet_handler(struct transport_forward *self,
				     uint32_t length, const uint8_t *data)
{
  assert(length > 0);
  debug("lsh_transport_service_packet_handler: %xs\n",
	length, data);
  if (data[0] == SSH_LSH_RANDOM_REQUEST)
    {
      struct simple_buffer buffer;
      uint32_t random_length;
      simple_buffer_init(&buffer, length-1, data+1);

      if (parse_uint32(&buffer, &random_length)
	  && parse_eod(&buffer))
	{
	  struct lsh_string *response;
	  uint32_t pos;

	  if (random_length > RANDOM_REQUEST_MAX)
	    random_length = RANDOM_REQUEST_MAX;

	  response = ssh_format("%c%r", SSH_LSH_RANDOM_REPLY, random_length, &pos);
	  lsh_string_write_random(response, pos, random_length);

	  /* Note: Bogus sequence number. */
	  transport_forward_service_packet(self, 0, STRING_LD(response));
	  lsh_string_free(response);
	}
      else
	transport_disconnect(&self->super, SSH_DISCONNECT_BY_APPLICATION,
			     "Received invalid packet from service layer.");
    }
  else
    transport_forward_packet(self, length, data);  
}

static struct lsh_transport_connection *
make_lsh_transport_connection(struct lsh_transport_config *config, int fd)
{
  NEW(lsh_transport_connection, self);
  /* FIXME: Packet handler that implements SSH_LSH_RANDOM_REQUEST,
     needed for X forwarding. */
  init_transport_forward(&self->super, kill_lsh_transport_connection,
			 &config->super, fd, fd,
			 lsh_transport_event_handler,
			 lsh_transport_service_packet_handler);

  self->state = STATE_HANDSHAKE;
  self->config = config;
  self->tried_empty_password = 0;
  self->expect_info_request = 0;
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

/* Handles decrypted packets. Replaced after userauth is complete. */
static int
lsh_transport_packet_handler(struct transport_connection *connection,
			     uint32_t seqno UNUSED, uint32_t length, const uint8_t *packet)
{
  CAST(lsh_transport_connection, self, connection);
  CAST(lsh_transport_config, config, connection->ctx);
  
  uint8_t msg;

  debug("Received packet: %xs\n", length, packet);
  assert(length > 0);

  msg = packet[0];

  switch(self->state)
    {
    case STATE_HANDSHAKE:
      fatal("Internal error.\n");
    case STATE_SERVICE_REQUEST:
      if (msg == SSH_MSG_SERVICE_ACCEPT)
	{
	  struct simple_buffer buffer;
	  uint32_t service_length;
	  const uint8_t *service;
	  
	  simple_buffer_init(&buffer, length-1, packet + 1);
	  if (parse_string(&buffer, &service_length, &service)
	      && parse_eod(&buffer)
	      && service_length == strlen(config->requested_service)
	      && 0 == memcmp(service, config->requested_service,
			     service_length))
	    {
	      if (config->userauth)
		{
		  self->state = STATE_USERAUTH;
		  start_userauth(self);
		}
	      else
		{
		  self->state = STATE_SERVICE_FORWARD;
		  start_service(self);
		}
	    }
	  else
	    transport_protocol_error(connection,
				     "Invalid SERVICE_ACCEPT message");
	}
      else
	transport_protocol_error(connection,
				 "Expected SERVICE_ACCEPT message");
      break;

    case STATE_USERAUTH:
      switch (msg)
	{
	case SSH_MSG_USERAUTH_SUCCESS:
	  if (length == 1)
	    {
	      verbose("Received USERAUTH_SUCCESS.\n");
	      self->state = STATE_SERVICE_FORWARD;
	      start_service(self);	      
	    }
	  else
	    transport_protocol_error(connection,
				     "Invalid USERAUTH_SUCCESS message");
	  break;

	case SSH_MSG_USERAUTH_BANNER:
	  {
	    struct simple_buffer buffer;
	    uint32_t msg_length;
	    const uint8_t *msg;
	    uint32_t language_length;
	    const uint8_t *language;
	    
	    simple_buffer_init(&buffer, length-1, packet + 1);
	    if (parse_string(&buffer, &msg_length, &msg)
		&& parse_string(&buffer, &language_length, &language)
		&& parse_eod(&buffer))
	      {
		/* Ignores the language tag */
		werror("%ups", msg_length, msg);
	      }
	    else
	      transport_protocol_error(connection,
				       "Invalid USERAUTH_BANNER message");
	    break;
	  }
	case SSH_MSG_USERAUTH_FAILURE:
	  {
	    struct simple_buffer buffer;
	    struct int_list *methods;
	    int partial;
	    simple_buffer_init(&buffer, length-1, packet + 1);
	    if ( (methods = parse_atom_list(&buffer, 17))
		 && parse_boolean(&buffer, &partial)
		 && parse_eod(&buffer))
	      {
		int pending = 0;

		self->expect_info_request = 0;

		if (partial)
		  /* Doesn't help us */
		  werror("Received SSH_MSH_USERAUTH_FAILURE "
			 "indicating partial success.\n");

		if (int_list_member (methods, ATOM_PASSWORD))
		  pending = try_password_auth(self);
		else if (int_list_member (methods, ATOM_KEYBOARD_INTERACTIVE))
		  pending = try_keyboard_interactive_auth(self);

		if (!pending)
		  transport_disconnect(connection,
				       SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
				       "No more auth methods available");
	      }
	    else
	      transport_protocol_error(connection,
				       "Invalid USERAUTH_FAILURE message");
	    break;
	  }
	case SSH_MSG_USERAUTH_INFO_REQUEST:
	  if (self->expect_info_request)
	    {
	      struct simple_buffer buffer;
	      simple_buffer_init(&buffer, length-1, packet + 1);
	      send_userauth_info_response(self, &buffer);
	    }
	  else
	    transport_protocol_error(connection,
				     "Unexpected USERAUTH_INFO_REQUEST");
	  break;

	default:
	  transport_send_packet(connection, TRANSPORT_WRITE_FLAG_PUSH,
				format_unimplemented(seqno));	  
	}
      break;
    case STATE_SERVICE_FORWARD:
      break;
    }

  return 1;
}

static void
start_userauth(struct lsh_transport_connection *self)
{
  CAST(lsh_transport_config, config, self->super.super.ctx);

  if (config->keypair)
    {
      struct keypair *key = config->keypair;
      
      /* Generates signature straight away. */

      /* The part of the request we sign */
      struct lsh_string *request
	= ssh_format("%c%z%z%a%c%a%S",
		     SSH_MSG_USERAUTH_REQUEST,
		     config->user,
		     config->service,
		     ATOM_PUBLICKEY,
		     1,
		     key->type, key->public);

      struct lsh_string *signed_data
	= ssh_format("%S%lS", self->super.super.session_id, request);

      struct lsh_string *signature = SIGN(key->private, key->type,
					  lsh_string_length(signed_data),
					  lsh_string_data(signed_data));
      lsh_string_free(signed_data);

      if (!signature)
	{
	  werror("Signing using the private key failed, RSA key too small!\n");
	  lsh_string_free (request);
	  goto no_pubkey;
	}
      request =	ssh_format("%flS%fS", 
			   request, 
			   signature);

      verbose("Requesting authentication of user `%z' using the `publickey' method.\n",
	      config->user);

      transport_send_packet(&self->super.super, TRANSPORT_WRITE_FLAG_PUSH,
			    request);
    }
  else
    {
    no_pubkey:
      /* Find out whether or not password authentication is supported. */
      transport_send_packet(&self->super.super, TRANSPORT_WRITE_FLAG_PUSH,
			    ssh_format("%c%z%z%a",
				       SSH_MSG_USERAUTH_REQUEST,
				       config->user,
				       config->service,
				       ATOM_NONE));
    }
}

#define MAX_PASSWORD 100

static int
try_password_auth(struct lsh_transport_connection *self)
{
  struct lsh_string *password
    = interact_read_password(ssh_format("Password for %lz: ",
					self->config->user));
  if (!password)
    return 0;

  /* Password empty? */
  if (!lsh_string_length(password))
    {
      /* NOTE: At least on some systems, the getpass function
       * sets the tty to raw mode, disabling ^C, ^D and the like.
       *
       * To be a little friendlier, we stop asking if the user
       * gives us the empty password twice.
       */
      if (self->tried_empty_password++)
	{
	  lsh_string_free (password);
	  return 0;
	}
    }

  random_add(RANDOM_SOURCE_SECRET, STRING_LD(password));

  verbose("Requesting authentication of user `%z' using the `password' method.\n",
	  self->config->user);

  transport_send_packet(&self->super.super, TRANSPORT_WRITE_FLAG_PUSH,
			ssh_format("%c%z%z%a%c%fS",
				   SSH_MSG_USERAUTH_REQUEST,
				   self->config->user,
				   self->config->service,
				   ATOM_PASSWORD, 0, password));
  return 1;
}

#define KBDINTERACT_MAX_PROMPTS 17
#define KBDINTERACT_MAX_LENGTH 200

static int
try_keyboard_interactive_auth(struct lsh_transport_connection *self)
{
  verbose("Requesting authentication of user `%z' using the `keyboard-interactive' method.\n",
	  self->config->user);

  transport_send_packet(&self->super.super, TRANSPORT_WRITE_FLAG_PUSH,
			ssh_format("%c%z%z%a%i%i",
				   SSH_MSG_USERAUTH_REQUEST,
				   self->config->user,
				   self->config->service,
				   /* Empty language tag and submethods */
				   ATOM_KEYBOARD_INTERACTIVE, 0, 0));

  self->expect_info_request = 1;
  return 1;
  
}

static struct lsh_string *
format_userauth_info_response(struct interact_dialog *dialog)
{
  uint32_t length;
  unsigned i;
  struct lsh_string *msg;
  uint32_t p;

  /* We need to format a message containing a variable number of
     strings. */

  /* First convert to utf8 */
  for (i = 0; i < dialog->nprompt; i++)
    dialog->response[i] = local_to_utf8(dialog->response[i], 1);
  
  for (i = length = 0; i < dialog->nprompt; i++)
    length += lsh_string_length(dialog->response[i]);

  msg = ssh_format("%c%i%lr", SSH_MSG_USERAUTH_INFO_RESPONSE, dialog->nprompt,
		   length + 4 * dialog->nprompt, &p);

  for (i = 0; i < dialog->nprompt; i++)
    {
      struct lsh_string *r = dialog->response[i];
      uint32_t rlength = lsh_string_length(r);
      lsh_string_write_uint32(msg, p, rlength);
      p += 4;
      lsh_string_write(msg, p, rlength, lsh_string_data(r));
      p += rlength;
    }
  assert (p == lsh_string_length(msg));
  
  return msg;
}

static void
send_userauth_info_response(struct lsh_transport_connection *self,
			    struct simple_buffer *buffer)
{
  const uint8_t *name;
  uint32_t name_length;

  const uint8_t *instruction;
  uint32_t instruction_length;
  /* Deprecated and ignored */
  const uint8_t *language;
  uint32_t language_length;

  /* Typed as "int" in the spec. Hope that means uint32_t? */  
  uint32_t nprompt; 
  
  if (parse_string(buffer, &name_length, &name)
      && parse_string(buffer, &instruction_length, &instruction)
      && parse_string(buffer, &language_length, &language)
      && parse_uint32(buffer, &nprompt))
    {
      struct interact_dialog *dialog;
      unsigned i;
      
      if (nprompt > KBDINTERACT_MAX_PROMPTS
	  || name_length > KBDINTERACT_MAX_LENGTH
	  || instruction_length > 10*KBDINTERACT_MAX_LENGTH)
	{
	too_large:
	  transport_disconnect(&self->super.super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Dialog too large.");

	  return;
	}

      dialog = make_interact_dialog(nprompt);

      for (i = 0; i < nprompt; i++)
	{
	  const uint8_t *prompt;
	  uint32_t prompt_length;
	  struct lsh_string *s;

	  if (! (parse_string(buffer, &prompt_length, &prompt)
		 && parse_boolean(buffer, &dialog->echo[i])))
	    {
	      KILL(dialog);
	      goto error;
	    }

	  if (prompt_length > KBDINTERACT_MAX_LENGTH)
	    {
	      KILL(dialog);
	      goto too_large;
	    }
	  s = low_utf8_to_local(prompt_length, prompt,
				utf8_replace | utf8_paranoid);
	  if (!s)
	    goto error;
	  
	  dialog->prompt[i] = s;
	}
      
      dialog->instruction
	= low_utf8_to_local(instruction_length, instruction,
			    utf8_replace | utf8_paranoid);
      
      if (!dialog->instruction)
	goto error;

      if (name_length > 0)
	{
	  /* Prepend to instruction */
	  struct lsh_string *s;
      
	  s = low_utf8_to_local(name_length, name,
				utf8_replace | utf8_paranoid);
	  if (!s)
	    goto error;

	  dialog->instruction = ssh_format("%lfS\n\n%lfS\n",
					   s, dialog->instruction);
	}
      else
	dialog->instruction = ssh_format("%lfS\n", dialog->instruction);

      if (!interact_dialog(dialog))
	{
	  transport_disconnect(&self->super.super,
			       SSH_DISCONNECT_AUTH_CANCELLED_BY_USER,
			       "Cancelled");

	  return;
	}
      
      transport_send_packet(&self->super.super, TRANSPORT_WRITE_FLAG_PUSH,
			    format_userauth_info_response(dialog));
    }
  else
    {
    error:
      transport_protocol_error(&self->super.super,
			       "Invalid USERAUTH_INFO_REQUEST");
    }
}

static void
start_service(struct lsh_transport_connection *self UNUSED)
{
  static const char hello[LSH_HELLO_LINE_LENGTH]
    = "LSH " STRINGIZE(LSH_HELLO_VERSION) " OK lsh-transport";

  /* Setting stdio fd:s to non-blocking mode is unfriendly in a
     general purpose program, that may share stdin and stdout with
     other processes. But we expect to get our own exclusive pipe when
     we are started by lsh. */

  /* Write hello message */
  if (!write_raw (STDOUT_FILENO, sizeof(hello), hello))
    {
      werror ("Writing local hello message failed: %e.\n", errno);
      exit (EXIT_FAILURE);
    }

  /* FIXME: We can probably get by with only stdout non-blocking. */
  io_set_nonblocking(STDIN_FILENO);
  io_set_nonblocking(STDOUT_FILENO);
  
  /* Replaces event_handler and packet_handler. */  
  transport_forward_setup(&self->super, STDIN_FILENO, STDOUT_FILENO);
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

  verbose("Connecting to %z:%z....\n", config->target, config->port);
  
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

  verbose("... connected.\n");

  /* We keep the socket in blocking mode */
  connection = make_lsh_transport_connection(config, s);
  gc_global(&connection->super.super.super);

  transport_handshake(&connection->super.super,
		      make_string(CLIENT_VERSION_LINE),
		      lsh_transport_line_handler);

  return 1;
}

/* For now, supports only a single key */
static struct keypair *
read_user_key(struct lsh_transport_config *config)
{
  struct lsh_string *tmp = NULL;
  struct lsh_string *contents;
  int fd;
  int algorithm_name;
  
  struct signer *s;
  struct verifier *v;

  trace("read_user_key\n");
  
  if (!config->userauth)
    return NULL;

  if (config->identity)
    {
      fd = open(config->identity, O_RDONLY);
      if (fd < 0)
	verbose("Failed to open `%z' for reading: %e.\n",
		config->identity, errno);
    }
  else
    {
      tmp = ssh_format("%lz/.lsh/identity", config->home);
      fd = open(lsh_get_cstring(tmp), O_RDONLY);
      if (fd < 0)
	werror("Failed to open `%S' for reading: %e.\n",
		tmp, errno);
      lsh_string_free(tmp);
    }

  if (fd < 0)
    return NULL;

  contents = io_read_file_raw(fd, 2000);

  if (!contents)
    {
      werror("Failed to read private key file: %e.\n", errno);
      close(fd);

      return NULL;
    }

  close(fd);

  /* FIXME: We should read the public key somehow, and decrypt the
     private key only if it is needed. */
  /* FIXME: Mix in the passphrase using
     random_add(RANDOM_SOURCE_SECRET, ...) */
  contents
    = spki_pkcs5_decrypt(alist_select_l(config->super.algorithms,
					2, ATOM_HMAC_SHA1, ATOM_HMAC_MD5, -1),
			 alist_select_l(config->super.algorithms,
					4, ATOM_3DES_CBC, ATOM_BLOWFISH_CBC,
					ATOM_TWOFISH_CBC, ATOM_AES256_CBC, -1),
			 contents);
  if (!contents)
    {
      werror("Decrypting private key failed.\n");
      return NULL;;
    }
  
  s = spki_make_signer(config->signature_algorithms, contents,
		       &algorithm_name);

  lsh_string_free(contents);
  
  if (!s)
    {
      werror("Invalid private key.\n");
      return NULL;
    }
  
  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  /* FIXME: SPKI support */

  /* Test key here? */  
  switch (algorithm_name)
    {	  
    case ATOM_DSA:
      return make_keypair(ATOM_SSH_DSS,
			  PUBLIC_KEY(v), s);
    case ATOM_DSA_SHA256:
      return make_keypair(ATOM_SSH_DSA_SHA256_LOCAL,
			  PUBLIC_KEY(v), s);
      
    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      return make_keypair(ATOM_SSH_RSA,
			  PUBLIC_KEY(v), s);
    case ATOM_RSA_PKCS1_MD5:
      werror("Key type rsa-pkcs1-md5 not supported.\n");
      return NULL;

    default:
      fatal("Internal error!\n");
    }
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
       (hash . "const struct nettle_hash *")))
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

	spki_key = PUBLIC_SPKI_KEY(v, 0);

	subject = spki_lookup_key(self->db, STRING_LD(spki_key), v);
	assert(subject);
	assert(subject->verifier);

	lsh_string_free(spki_key);
	break;
      }

    case ATOM_SSH_DSA_SHA256_LOCAL:
      {
	struct lsh_string *spki_key;
	struct verifier *v = make_ssh_dsa_sha256_verifier(key_length, key);

	if (!v)
	  {
	    werror("do_lsh_lookup: Invalid ssh-dsa-sha256 key.\n");
	    return NULL;
	  }

	spki_key = PUBLIC_SPKI_KEY(v, 0);

	subject = spki_lookup_key(self->db, STRING_LD(spki_key), v);
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

	spki_key = PUBLIC_SPKI_KEY(v, 0);
	subject = spki_lookup_key(self->db, STRING_LD(spki_key), v);
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
      struct lsh_string *fingerprint;
      struct lsh_string *babble;
      
      verbose("SPKI authorization failed.\n");
      if (!self->config->sloppy)
	{
	  werror("Server's hostkey is not trusted. Disconnecting.\n");
	  return NULL;
	}

      fingerprint = 
	    lsh_string_colonize( 
				ssh_format( "%lfxS", 
					    hash_string_l(&nettle_md5,
							  key_length, key)
					    ), 
				2, 
				1  
				);

      babble = 
	    lsh_string_bubblebabble( 
				    hash_string_l(&nettle_sha1,
						  key_length, key),
				    1 
				    );

      /* Ok, let's see if we want to use this untrusted key. Display
	 fingerprint. */
      if (!werror_quiet_p() && !interact_yes_or_no(
	       ssh_format("Received unauthenticated key for host %lz\n"
			  "Key details:\n"
			  "Bubble Babble: %lS\n"
			  "Fingerprint:   %lS\n"
			  "Do you trust this key? (y/n) ",
			  self->config->target, babble, fingerprint), 0))
	{
	  lsh_string_free(fingerprint);
	  lsh_string_free(babble);
	  return NULL;
	}

      acl = lsh_string_format_sexp(0, "(acl(entry(subject%l)%l))",
				   subject->key_length, subject->key,
				   STRING_LD(self->access));
      
      /* FIXME: Seems awkward to pick the acl apart again. */
      
      /* Remember this key. We don't want to ask again for key re-exchange */
      spki_add_acls(self->db, STRING_LD(acl));

      /* FIXME: When --host-db-update is given explicitly together
	 with -q, *always* append the new acl to the given file? */
      if (self->config->capture_fd >= 0
	  && interact_yes_or_no(ssh_format("Remember key and trust it in the future? (y/n) "),
				0))
	{
	  /* Write an ACL to disk. */
	  time_t now = time(NULL);
	  const char *sexp_conv;
	  const char *args[] = { "sexp-conv", "-s", "advanced", "--lock", NULL };

	  struct lsh_string *entry
	    = ssh_format("\n; ACL for host %lz\n"
			 "; Date: %lz\n"
			 "; Fingerprint: %lS\n"
			 "; Bubble-babble: %lS\n"
			 "%lS\n",
			 self->config->target, ctime(&now), fingerprint, babble, acl);
	  
	  GET_FILE_ENV(sexp_conv, SEXP_CONV);

	  if (!lsh_popen_write(sexp_conv, args, self->config->capture_fd, STRING_LD(entry)))
	    werror("Writing acl entry failed.\n");

	  lsh_string_free(entry);
	}
      lsh_string_free(fingerprint);
      lsh_string_free(babble);
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
  self->hash = &nettle_sha1;
  
  return self;
}

/* Initialize the spki database and the access tag. Called after
   options parsing. */
static void
read_host_acls(struct lsh_transport_lookup_verifier *self,
	       const char *file)
{
  struct lsh_string *contents;
  int fd;
  const char *sexp_conv;
  const char *args[] = { "sexp-conv", "-s", "canonical", NULL };

  assert(self->config->target);
  
  self->access = make_ssh_hostkey_tag(self->config->target);
  self->db = make_spki_context(self->config->signature_algorithms);
  
  fd = open(file, O_RDONLY);
  if (fd < 0)
    {
      if (errno == ENOENT)
	{
	  verbose("Failed to open `%z' for reading: %e.\n", file, errno);
	  if (!self->config->host_acls)
	    {
	      struct stat sbuf;
	      struct lsh_string *known_hosts;

	      known_hosts = ssh_format("%lz/.lsh/known_hosts", self->config->home);

	      if (stat(lsh_get_cstring(known_hosts), &sbuf) == 0)
		{
		  werror("You have an old known-hosts file `%S'.\n"
			 "To work with lsh-2.0 and alter, run the lsh-upgrade script,\n"
			 "which will convert that to a new host-acls file.\n",
			 known_hosts);
		}
	      lsh_string_free(known_hosts);
	    }
	}
      else
	werror("Failed to open `%z' for reading: %e.\n",
	       file, errno);
      return;
    }

  GET_FILE_ENV(sexp_conv, SEXP_CONV);
  
  contents = lsh_popen_read(sexp_conv, args, fd, 5000);
  
  if (!contents)
    {
      werror("Failed to read host-acls file `%z': %e.\n",
	     file, errno);
      close(fd);
      return;
    }

  close(fd);

  /* Ignores any error */
  spki_add_acls(self->db, STRING_LD(contents));

  lsh_string_free(contents);
}

/* Option parsing */

const char *argp_program_version
= "lsh-transport (" PACKAGE_STRING ")";

const char *argp_program_bug_address = BUG_ADDRESS;

enum {
  ARG_NOT = 0x400,

  /* Transport options */
  OPT_SLOPPY = 0x201,
  OPT_STRICT,
  OPT_HOST_DB,
  OPT_HOST_DB_UPDATE,

  /* Userauth options */
  OPT_USERAUTH,
  OPT_PUBLICKEY,

  /* FIXME: Enable/disable password, kbdinteract, etc */

  /* Service options */
  OPT_SERVICE,
  OPT_ASKPASS,
};

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
  { "host-db-update", OPT_HOST_DB_UPDATE, "Filename", 0,
    "File that ACLs for new keys are appended to. "
    "The default is ~/.lsh/host-acls.", 0 },
  
  /* User authentication */
  { "user", 'l', "NAME", 0, "Login as this user.", 0 },
  { "userauth", OPT_USERAUTH, NULL, 0,
    "Enable user authentication (default).", 0},
  { "no-userauth", OPT_USERAUTH | ARG_NOT, NULL, 0,
    "Disable user authentication.", 0},
  
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "service" , OPT_SERVICE, "Name", 0, "Service to request. Default is `ssh-connection'.", 0},

  { "askpass", OPT_ASKPASS, "Program", 0,
    "Program to use for reading passwords. "
    "Should be an absolute filename.", 0 },

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
      state->child_inputs[0] = self->algorithms;
      state->child_inputs[1] = self->werror_config;
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
      if (!werror_init(self->werror_config))
	argp_failure(state, EXIT_FAILURE, errno, "Failed to open log file");

      self->super.kexinit
	= make_kexinit_info(self->kex_algorithms,
			    self->algorithms->hostkey_algorithms,
			    self->algorithms->crypto_algorithms,
			    self->algorithms->mac_algorithms,
			    self->algorithms->compression_algorithms,
			    make_int_list(0, -1));

      self->requested_service
	= self->userauth ? "ssh-userauth" : self->service;

      {
	struct lsh_string *host_acls;
	const char *host_db_update;

	if (self->host_acls)
	  host_acls = make_string(self->host_acls);
	else
	  host_acls = ssh_format("%lz/.lsh/host-acls", self->home);

	read_host_acls(self->host_db, lsh_get_cstring(host_acls));

	if (self->sloppy)
	  {
	    if (self->capture_file)
	      host_db_update = self->capture_file;
	    else
	      host_db_update = lsh_get_cstring(host_acls);
	
	    self->capture_fd = open(host_db_update,
				    O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if (self->capture_fd < 0)
	      werror("Opening `%z' for writing failed: %e.\n",
		     host_db_update, errno);
	  }
	lsh_string_free(host_acls);
      }
      
      self->keypair = read_user_key(self);
      
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

    case OPT_HOST_DB_UPDATE:
      self->capture_file = arg;
      break;

    case 'l':
      self->user = arg;
      break;

    case OPT_USERAUTH:
      self->userauth = 1;
      break;
    case OPT_USERAUTH | ARG_NOT:
      self->userauth = 0;
      break;

    case 'i':
      self->identity = arg;
      break;

    case OPT_SERVICE:
      self->service = arg;
      break;

    case OPT_ASKPASS:
      interact_set_askpass(arg);
      break;
    }
  return 0;
}

static const struct argp_child
main_argp_children[] =
{
  { &algorithms_argp, 0, "", 0 },
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

  if (!unix_interact_init(0))
    return EXIT_FAILURE;

  io_init();

  config = make_lsh_transport_config();
  if (!config)
    return EXIT_FAILURE;

  if (!random_init_user(config->home))
    {
      werror("No randomness generator available.\n");
      return EXIT_FAILURE;
    }
  
  argp_parse(&main_argp, argc, argv, 0, NULL, config);

  if (!lsh_connect(config))
    return EXIT_FAILURE;

  io_run();

  return EXIT_SUCCESS;
}
