/* client_userauth.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balazs Scheidler, Niels Möller
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

#include "userauth.h"

#include "charset.h"
#include "command.h"
#include "format.h"
#include "parse.h"
#include "password.h"
#include "publickey_crypto.h"
#include "service.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* FIXME: For now, use only password authentication. A better method
 * would be to first send a set of publickey authentication requests
 * for the available keys (for some configurable value of
 * "available"). This is analogous to unlocking a door by first
 * examining the keys on one's keyring to see if any of them can be
 * inserted into the lock. Preferably, at this point one should use
 * spki hashed public keys rather than the public keys themselves.
 *
 * Next we wait for SSH_MSH_USERAUTH_FAILURE or SSH_MSG_USERAUTH_PK_OK
 * messages. If any of the keys is recognized, we compute a signature
 * and send it to the server (analogously to inserting the key into
 * the lock and turning it around).
 *
 * If none of the keys were recognized, or if no keys were available
 * from the start, we ask the user for a password and attempt to log
 * in using that. */

/* Forward declaration */
struct client_userauth; 

#include "client_userauth.c.x"

static struct packet_handler *make_banner_handler(void);

static struct lsh_string *format_userauth_password(struct lsh_string *name,
						   int service,
						   struct lsh_string *passwd,
						   int free)
{
  return ssh_format(free ? "%c%S%a%a%c%fS" : "%c%S%a%a%c%S",
		    SSH_MSG_USERAUTH_REQUEST,
		    name,
		    service,
		    ATOM_PASSWORD,
		    0,
		    passwd);
}

static struct lsh_string *
format_userauth_publickey_query(struct lsh_string *name,
				UINT32 service,
				UINT32 keytype,
				struct lsh_string *public)
{
  return ssh_format("%c%S%a%a%c%a%S",
		    SSH_MSG_USERAUTH_REQUEST,
		    name,
		    service,
		    ATOM_PUBLICKEY,
		    0,
		    keytype,
		    public);
}

static struct lsh_string *
format_userauth_publickey(struct lsh_string *name,
			  UINT32 service,
			  UINT32 keytype,
			  struct lsh_string *public)
{
  return ssh_format("%c%S%a%a%c%a%S",
		    SSH_MSG_USERAUTH_REQUEST,
		    name,
		    service,
		    ATOM_PUBLICKEY,
		    1,
		    keytype,
		    public);
}

/* ;; GABA:
   (class
     (name client_userauth_method)
     (vars
       ; set up message handlers
       (setup method int "struct client_userauth *userauth"
                         "struct ssh_connection *connection")
       ; send authentication request
       (send method void "struct client_userauth *userauth" 
                         "struct ssh_connection *connection")
       ; clean up message handlers
       (cleanup method void "struct client_userauth *userauth"
                            "struct ssh_connection *connection")))
*/
#if 0
#define CLIENT_USERAUTH_SETUP(m, u, c) \
  ((m->setup) ? ((m)->setup(m, u, c)) : 1)
#define CLIENT_USERAUTH_SEND(m, u, c) \
  ((m->send) ? ((m)->send(m, u, c)) : (void) 0)
#define CLIENT_USERAUTH_CLEANUP(m, u, c) \
  ((m->cleanup) ? ((m)->cleanup(m, u, c)) : (void) 0)
#endif

/* Called when we receive a USERAUTH_FAILURE message. It will
 * typically either try again, or raise EXC_USERAUTH. */

/* GABA:
   (class
     (name client_userauth_failure)
     (vars
       (failure method void)))
*/

#define CLIENT_USERAUTH_FAILURE(f) ((f)->failure((f)))

/* Almost like a command, but returns a failure handler. */
/* GABA:
   (class
     (name client_userauth_method)
     (vars
       (type . int)
       (login method "struct client_userauth_failure *"
                     "struct client_userauth *u"
                     "struct ssh_connection *c"
		     "struct exception_handler *e")))
*/

#define CLIENT_USERAUTH_LOGIN(m, u, c, e) \
  ((m)->login((m), (u), (c), (e)))


#if 0
/* ;; GABA:
   (class
     (name client_userauth)
     (super command)
     (vars
       (username string)            ; Remote user name to authenticate as.
       (service_name simple int)    ; Service we want to access .
       (current_method simple int)
       (methods object alist)       ; authentication methods
            
       ; FIXME: Keys to try
       ))
*/
#endif

/* Takes a connection as argument, and attempts to login. It does this
 * by trying each METHOD in turn. As soon as one succeeds, the
 * connection is returned. When a method fails (raising a EXC_USERAUTH
 * exception), we try the next method. If all methods fail, we raise
 * EXC_USERAUTH. */

/* GABA:
   (class
     (name client_userauth)
     (super command)
     (vars
       (username string)            ; Remote user name to authenticate as.
       (service_name simple int)    ; Service we want to access.
       (methods object object_list) ; Authentication methods, in order.
       ))
*/

/* GABA:
   (class
     (name client_userauth_state)
     (vars
       (userauth object client_userauth)
       (connection object ssh_connection)
       (failure object client_userauth_failure)
       (current . unsigned)))       ; Current method
*/

static struct client_userauth_state *
make_client_userauth_state(struct client_userauth *userauth,
			   struct ssh_connection *connection)
{
  NEW(client_userauth_state, self);

  self->connection = connection;
  self->userauth = userauth;
  self->failure = NULL;
  self->current = 0;

  return self;
}

/* GABA:
   (class
     (name userauth_packet_handler)
     (super packet_handler)
     (vars
       (state object client_userauth_state)))
*/


/* GABA:
   (class
     (name userauth_success_handler)
     (super packet_handler)
     (vars
       (c object command_continuation)))
*/

static void
do_userauth_success(struct packet_handler *c,
		    struct ssh_connection *connection,
		    struct lsh_string *packet)
{
  CAST(userauth_success_handler, self, c);
  struct simple_buffer buffer;

  unsigned msg_number;
    
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_SUCCESS)
      && parse_eod(&buffer))
    {
      unsigned i;
      
      lsh_string_free(packet);

      werror("User authentication successful.\n");

      for (i = SSH_FIRST_USERAUTH_GENERIC; i < SSH_FIRST_CONNECTION_GENERIC; i++) 
	connection->dispatch[i] = connection->fail;
      
      COMMAND_RETURN(self->c, connection);
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid USERAUTH_SUCCESS message");
    }
}

static struct packet_handler *
make_success_handler(struct command_continuation *c)
{
  NEW(userauth_success_handler, self);

  self->super.handler = do_userauth_success;
  self->c = c;

  return &self->super;
}


/* GABA:
   (class
     (name failure_handler)
     (super userauth_packet_handler)
     (vars
       (e object exception_handler)))
*/


/* Arbitrary limit on list length */
#define USERAUTH_MAX_METHODS 47

static void
do_userauth_failure(struct packet_handler *c,
		    struct ssh_connection *connection,
		    struct lsh_string *packet)
{
  CAST(userauth_packet_handler, self, c);
  struct simple_buffer buffer;

  unsigned msg_number;
  struct int_list *methods = NULL;
  int partial_success;
    
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_FAILURE)
      && ( (methods = parse_atom_list(&buffer, USERAUTH_MAX_METHODS)) )
      && parse_boolean(&buffer, &partial_success)
      && parse_eod(&buffer))
    {
      unsigned i;

      lsh_string_free(packet);
      
      if (partial_success)
	/* Doesn't help us */
	werror("Received SSH_MSH_USERAUTH_FAILURE "
	       "indicating partial success.\n");

      while (self->state->current < LIST_LENGTH(self->state->userauth->methods))
	{
	  CAST_SUBTYPE(client_userauth_method, method,
		       LIST(self->state->userauth->methods)[self->state->current]);
	  
	  for(i = 0; i < LIST_LENGTH(methods); i++)
	    {
	      if (LIST(methods)[i] == method->type)
		goto done;
	    }

	  /* Skip this method */
	  self->state->current++;
	}
      
    done:
      CLIENT_USERAUTH_FAILURE(self->state->failure);
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(connection->e, "Invalid USERAUTH_FAILURE message.");
    }
  
  KILL(methods);	
}

static struct packet_handler *
make_failure_handler(struct client_userauth_state *state)
{
  NEW(userauth_packet_handler, self);

  self->super.handler = do_userauth_failure;
  self->state = state;

  return &self->super;
}

static void
do_userauth_banner(struct packet_handler *self,
		   struct ssh_connection *connection UNUSED,
		   struct lsh_string *packet)
{
  struct simple_buffer buffer;

  unsigned msg_number;
  UINT32 length;
  UINT8 *msg;

  UINT32 language_length;
  UINT8 *language;
  
  CHECK_TYPE(packet_handler, self);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_BANNER)
      && parse_string(&buffer, &length, &msg)
      && parse_string(&buffer, &language_length, &language)
      && parse_eod(&buffer))
    {
      /* Ignore language tag */
      werror("%ups", length, msg);
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid USERAUTH_SUCCESS message");

  lsh_string_free(packet);
}

static struct packet_handler *make_banner_handler(void)
{
  NEW(packet_handler, self);

  self->handler = do_userauth_banner;
  
  return self;
}

/* GABA:
   (class
     (name client_exc_userauth)
     (super exception_handler)
     (vars
       (state object client_userauth_state)))
*/

static void
do_client_exc_userauth(struct exception_handler *s,
		       const struct exception *e)
{
  CAST(client_exc_userauth, self, s);

  if ( (e->type & EXC_USERAUTH) 
       && (self->state->current < LIST_LENGTH(&self->state->userauth->methods)))
    {
      CAST_SUBTYPE(client_userauth_method, method,
		   LIST(self->state->userauth->methods)[self->state->current]);

      self->state->current++;
      
      self->state->failure
	= CLIENT_USERAUTH_LOGIN(method, self->state->userauth,
				self->state->connection, s);
    }
  else
    EXCEPTION_RAISE(s->parent, e);
}

static struct exception_handler *
make_client_exc_userauth(struct client_userauth_state *state,
			 struct exception_handler *parent,
			 const char *context)
{
  NEW(client_exc_userauth, self);
  self->super.parent = parent;
  self->super.raise = do_client_exc_userauth;
  self->super.context = context;

  self->state = state;

  return &self->super;
}

static void
do_client_userauth(struct command *s,
		   struct lsh_object *x,
		   struct command_continuation *c,
		   struct exception_handler *e)
{
  CAST(client_userauth, self, s);
  CAST(ssh_connection, connection, x);
  
  struct client_userauth_state *state
    = make_client_userauth_state(self, connection);

  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS]
    = make_success_handler(c);
  connection->dispatch[SSH_MSG_USERAUTH_FAILURE]
    = make_failure_handler(state);
  connection->dispatch[SSH_MSG_USERAUTH_BANNER]
    = make_banner_handler();

  assert(LIST_LENGTH(self->methods));
  {
    CAST_SUBTYPE(client_userauth_method, method,
		 LIST(self->methods)[0]);
    state->failure = CLIENT_USERAUTH_LOGIN(method, self,
					   connection,
					   make_client_exc_userauth(state, e,
								    HANDLER_CONTEXT));
  }
}


struct command *make_client_userauth(struct lsh_string *username,
				     int service_name,
				     struct object_list *methods)
{
  NEW(client_userauth, self);

  self->super.call = do_client_userauth;
  self->username = username;
  self->service_name = service_name;
  self->methods = methods;

  return &self->super;
}


/* Password authentication */

#define MAX_PASSWD 100

static void
send_password(struct client_userauth *userauth,
	      struct ssh_connection *connection,
	      struct exception_handler *e)
{
  struct lsh_string *passwd
    = read_password(MAX_PASSWD,
                    ssh_format("Password for %lS: ",
                               userauth->username), 1);

  if (passwd)
    C_WRITE(connection,
	    format_userauth_password(local_to_utf8(userauth->username, 0),
				     userauth->service_name,
				     local_to_utf8(passwd, 1),
				     1));
  
  else
    {
      static const struct exception no_passwd =
	STATIC_EXCEPTION(EXC_USERAUTH, "No password supplied.");

      EXCEPTION_RAISE(e, &no_passwd);
    }
}

/* GABA:
   (class
     (name client_password_state)
     (super client_userauth_failure)
     (vars
       (userauth object client_userauth)
       (connection object ssh_connection)
       (e object exception_handler)))
*/


static void
do_password_failure(struct client_userauth_failure *s)
{
  CAST(client_password_state, self, s);

  send_password(self->userauth, self->connection, self->e);
}

static struct client_userauth_failure *
make_client_password_state(struct client_userauth *userauth,
			   struct ssh_connection *connection,
			   struct exception_handler *e)
{
  NEW(client_password_state, self);
  self->super.failure = do_password_failure;
  self->userauth = userauth;
  self->connection = connection;
  self->e = e;

  return &self->super;
}

static struct client_userauth_failure *
do_password_login(struct client_userauth_method *s UNUSED,
		  struct client_userauth *userauth,
		  struct ssh_connection *connection,
		  struct exception_handler *e)
{
  send_password(userauth, connection, e);
  return make_client_password_state(userauth, connection, e);
}

struct client_userauth_method *
make_client_password_auth(void)
{
  NEW(client_userauth_method, self);
  self->type = ATOM_PASSWORD;
  self->login = do_password_login;
  
  return self;
}


/* Publickey authentication. */

/* NOTE: We try only the first key for which we receive a USERAUTH_PK_OK */

/* GABA:
   (class
     (name client_publickey_method)
     (super client_userauth_method)
     (vars
       (keys object object_list)))
*/

/* GABA:
   (class
     (name client_publickey_state)
     (super client_userauth_failure)
     (vars
       (userauth object client_userauth)
       (connection object ssh_connection)
       (keys object object_list)
       ; Number of keys for which we have received either
       ; a USERAUTH_FAILURE or USERAUTH_PK_OK message.
       (done . UINT32)
       ; Non-zero if we have computed and sent a signature.
       (pending . int)
       (e object exception_handler)))
*/

static void
client_publickey_next(struct client_publickey_state *state)
{
  state->done++;
  if (state->done == LIST_LENGTH(state->keys))
    {
      static const struct exception publickey_auth_failed =
	STATIC_EXCEPTION(EXC_USERAUTH, "Public key userauth failed.");
	  
      state->connection->dispatch[SSH_MSG_USERAUTH_PK_OK]
	= state->connection->fail;
      if (!state->pending)
	EXCEPTION_RAISE(state->e, &publickey_auth_failed);
    }
}

static void
do_publickey_failure(struct client_userauth_failure *s)
{
  CAST(client_publickey_state, self, s);

  client_publickey_next(self);
}
  
static struct client_publickey_state *
make_client_publickey_state(struct client_userauth *userauth,
			    struct ssh_connection *connection,
			    struct object_list *keys,
			    struct exception_handler *e)
{
  NEW(client_publickey_state, self);
  self->super.failure = do_publickey_failure;
  self->userauth = userauth;
  self->connection = connection;
  self->keys = keys;
  self->done = 0;
  self->pending = 0;
  self->e = e;

  return self;
}

/* GABA:
   (class
     (name userauth_pk_ok_handler)
     (super packet_handler)
     (vars
       (state object client_publickey_state)))
*/
  
static void 
do_userauth_pk_ok(struct packet_handler *s,
		  struct ssh_connection *connection,
		  struct lsh_string *packet UNUSED)
{
  CAST(userauth_pk_ok_handler, self, s);

  struct simple_buffer buffer;

  unsigned msg_number;
  int algorithm;
  UINT32 keyblob_length;
  UINT8 *keyblob;

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_PK_OK)
      && parse_atom(&buffer, &algorithm)
      && parse_string(&buffer, &keyblob_length, &keyblob)
      && parse_eod(&buffer))
    {
      CAST(keypair, key, LIST(self->state->keys)[self->state->done]);
      verbose("SSH_MSG_USERAUTH_PK_OK received\n");
	  
      if ( (key->type == algorithm)
	   && !lsh_string_cmp_l(key->public, keyblob_length, keyblob) )
	{
	  struct lsh_string *request;
	  struct lsh_string *signed_data;
    
#if DATAFELLOWS_WORKAROUNDS
	  if (connection->peer_flags & PEER_USERAUTH_REQUEST_KLUDGE)
	    request = format_userauth_publickey(local_to_utf8(self->state->userauth->username, 0),
						ATOM_SSH_USERAUTH,
						key->type,
						key->public);
#endif  
	  else
	    request = format_userauth_publickey(local_to_utf8(self->state->userauth->username, 0),
						self->state->userauth->service_name,
						key->type,
						key->public);
	  signed_data = ssh_format("%S%lS", connection->session_id, request);
	  request = ssh_format("%flS%fS", 
			       request, 
			       SIGN(key->private, signed_data->length, signed_data->data));
	  lsh_string_free(signed_data);
	  C_WRITE(connection, request);
	  self->state->pending = 1;
	}
      else
	werror("client_userauth.c: Unexpected key in USERAUTH_PK_OK message.\n");

      lsh_string_free(packet);
      client_publickey_next(self->state);
    }
  else
    {
      lsh_string_free(packet);
      PROTOCOL_ERROR(self->state->e, "Invalid USERAUTH_PK_OK message");
    }
}

static struct packet_handler *
make_pk_ok_handler(struct client_publickey_state *state)
{
  NEW(userauth_pk_ok_handler, self);

  self->super.handler = do_userauth_pk_ok;
  self->state = state;

  return &self->super;
}

static struct client_userauth_failure *
do_publickey_login(struct client_userauth_method *s,
		   struct client_userauth *userauth,
		   struct ssh_connection *connection,
		   struct exception_handler *e)
{
  CAST(client_publickey_method, self, s);

  assert(LIST_LENGTH(self->keys));
  
#if 0
  if (!LIST_LENGTH(self->keys))
    {
      static const struct exception no_keys =
	STATIC_EXCEPTION(EXC_USERAUTH, "No keys");
      
      werror("do_publickey_login: No keys!\n");
      EXCEPTION_RAISE(e, &no_keys);
    }
  else
#endif
    
    {
      struct client_publickey_state *state =
	make_client_publickey_state(userauth,
				    connection,
				    self->keys,
				    e);
      unsigned i;
      
      for (i = 0; i < LIST_LENGTH(self->keys); i++)
	{
	  CAST(keypair, key, LIST(self->keys)[i]);

	  C_WRITE(connection, 
		  format_userauth_publickey_query(local_to_utf8(userauth->username, 0),
						  userauth->service_name,
						  key->type, key->public));
	}
      connection->dispatch[SSH_MSG_USERAUTH_PK_OK] = make_pk_ok_handler(state);
      return &state->super;
    }
}

#if 0
static void
do_cleanup_publickey(struct client_userauth_method *c,
		     struct client_userauth *userauth UNUSED,
		     struct ssh_connection *connection)
{
  CAST(client_publickey_method, self, c);

  self->current_key++;
  connection->dispatch[SSH_MSG_USERAUTH_PK_OK] = connection->fail;
}

static void
do_send_publickey(struct client_userauth_method *c, 
		  struct client_userauth *userauth,
		  struct ssh_connection *connection)
{
  CAST(client_publickey_method, self, c);

  if (LIST_LENGTH(self->keys) > self->current_key)
    {
      CAST(keypair, key, LIST(self->keys)[self->current_key]);

      C_WRITE(connection, 
	      format_userauth_publickey_query(local_to_utf8(userauth->username, 0),
					      userauth->service_name,
					      key->type, key->public));
    }
}
#endif

struct client_userauth_method *
make_client_publickey_auth(struct object_list *keys)
{
  NEW(client_publickey_method, self);

  self->super.login = do_publickey_login;
  self->keys = keys;
  
  return &self->super;
}
