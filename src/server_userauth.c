/* server_userauth.c
 *
 * Server side user authentication. */

#include "userauth.h"

#include "connection.h"
#include "format.h"
#include "ssh.h"
#include "xalloc.h"

#include <assert.h>

#include "server_userauth.c.x"

/* FIXME: Supports only password authentication so far. There should
 * be some abstraction for handling several authentication methods. */

/* GABA:
   (class
     (name userauth_service)
     (super command)
     (vars
       (advertised_methods object int_list)
       (methods object alist)
       (services object alist)))
*/

/* Max number of attempts */
#define AUTH_ATTEMPTS 20

/* FIXME: There are no timeouts for authentications. The callouts in
 * io.c could be used for timeouts, but it's not clear how the timeout
 * handler can close the right connection. Using the right exception
 * handler could work. */

/* NOTE: Here we assume that services and authentication methods are
 * orthogonal. I.e. every supported authentication method is accepted
 * for every supported service. */

/* GABA:
   (class
     (name userauth_handler)
     (super packet_handler)
     (vars
       ; Attempts left 
       ;; (attempts simple int)

       ; What to do after successful authentication
       (c object command_continuation)
       ; or failed.
       (e object exception_handler)
       
       ; Methods advertised in failure messages
       ;; (advertised_methods object int_list)

       ; Maps authentication methods to userath objects
       (methods object alist)

       ; Maps services to commands
       (services object alist)))
*/

/* FIXME: Perhaps this should use a two-dimensional lookup, and call
 * an authentication object depending on both service and method? */

/* NOTE: This implementation does not use any partial successes. As
 * soon as one authentication request is successful, the
 * entire authentication process succeeds. */
static void
do_handle_userauth(struct packet_handler *c,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  CAST(userauth_handler,  closure, c);
  struct simple_buffer buffer;

  unsigned msg_number;
  struct lsh_string *user;
  int requested_service;
  int method;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_REQUEST)
      && ( (user = parse_string_copy(&buffer)) )
      && parse_atom(&buffer, &requested_service)
      && parse_atom(&buffer, &method))
    {
      CAST_SUBTYPE(userauth, auth, ALIST_GET(closure->methods, method));
      CAST_SUBTYPE(command, service,
		   ALIST_GET(closure->services, requested_service));
      
      if (!(auth && service))
	{
	  static const struct exception userauth_failed
	    = STATIC_EXCEPTION(EXC_USERAUTH,
			       "Unknown auth method or service.");
	  
	  EXCEPTION_RAISE(closure->e, &userauth_failed);
	  return;
	}

      AUTHENTICATE(auth, connection, user, &buffer,
		   make_delay_continuation(service, closure->c),
		   closure->e);
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid USERAUTH message.");

  lsh_string_free(packet);
}


/* FIXME: This code doesn't handle authentication methods where the
 * result (continuation or exception) is not invoked immediately.
 * There are two problems:
 *
 * 1. Requests are not necessarily replied to in order. That is bad,
 * but can probably be fixed fairly easily the same way that it is
 * done for GLOBAL_REQUEST messages.
 *
 * 2. Packets that are received after a sucessful USERAUTH_REQUEST
 * message, but before it is processed and replied to, must somehow be
 * queued until we know that the user is authenticated for some
 * service to receive them.
 *
 * The latter problems seems a little tricky; perhaps we can keep some
 * state at a higher level where we stop reading on the connection as
 * soon as we have received the first non-userauth packet? But this
 * doesn't mix well with the buffered style read handler. */

/* GABA:
   (class
     (name userauth_continuation)
     (super command_frame)
     (vars
       (connection object ssh_connection)))
*/

static void
do_userauth_continuation(struct command_continuation *s,
			 struct lsh_object *value)
{
  CAST(userauth_continuation, self, s);
  CAST(delayed_apply, action, value);
  
  assert(action);

  /* Access granted. */

  C_WRITE(self->connection, format_userauth_success());

  /* Ignore any further userauth messages. */
  self->connection->dispatch[SSH_MSG_USERAUTH_REQUEST]
    = self->connection->ignore;

  FORCE_APPLY(action, self->super.up, self->super.e); 
}

static struct command_continuation *
make_userauth_continuation(struct ssh_connection *connection,
			   struct command_continuation *c,
			   struct exception_handler *e)
{
  NEW(userauth_continuation, self);
  self->super.super.c = do_userauth_continuation;
  self->super.up = c;
  self->super.e = e;
  
  self->connection = connection;
  return &self->super.super;
}
      

/* GABA:
   (class
     (name exc_userauth_handler)
     (super exception_handler)
     (vars
       (connection object ssh_connection)

       ; Methods advertised in failure messages
       (advertised_methods object int_list)

       ; Allowed number of failures before disconnecting
       (attempts . unsigned)))
*/

static void
do_exc_userauth_handler(struct exception_handler *s,
			const struct exception *x)
{
  CAST(exc_userauth_handler, self, s);

  switch(x->type)
    {
    default:
      EXCEPTION_RAISE(self->super.parent, x);
      break;
    case EXC_USERAUTH:
      if (self->attempts)
	{
	  self->attempts--;
	  C_WRITE(self->connection,
		  format_userauth_failure(self->advertised_methods, 0));
	}
      else
	{
	  EXCEPTION_RAISE(self->connection->e,
			  make_protocol_exception(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
						  "Access denied"));
	}
      break;
    case EXC_USERAUTH_SPECIAL:
      {
	CAST_SUBTYPE(userauth_special_exception, e, x);
	/* NOTE: We can't NULL e->reply, since the exception it is supposed to be constant.
	 * So we have to dup it, to make the gc happy. */
	C_WRITE(self->connection, lsh_string_dup(e->reply));

	break;
      }
    }
}

static struct exception_handler *
make_exc_userauth_handler(struct ssh_connection *connection,
			  struct int_list *advertised_methods,
			  unsigned attempts,
			  struct exception_handler *parent)
{
  NEW(exc_userauth_handler, self);
  self->super.raise = do_exc_userauth_handler;
  self->super.parent = parent;
  
  self->connection = connection;
  self->advertised_methods = advertised_methods;
  self->attempts = attempts;

  return &self->super;
}

	  
static void do_userauth(struct command *s, 
			struct lsh_object *x,
			struct command_continuation *c,
			struct exception_handler *e)
{
  CAST(userauth_service, self, s);
  CAST(ssh_connection, connection, x);
  NEW(userauth_handler, auth);
  
  auth->super.handler = do_handle_userauth;
  /* auth->advertised_methods = self->advertised_methods; */
  auth->methods = self->methods;
  auth->services = self->services;
  /* auth->attempts = AUTH_ATTEMPTS; */
  
  auth->c = make_once_continution(NULL,
				  make_userauth_continuation(connection,
							     c, e));
  auth->e = make_exc_userauth_handler(connection,
				      self->advertised_methods,
				      AUTH_ATTEMPTS, e);
  
  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] = &auth->super;
}

struct command *make_userauth_service(struct int_list *advertised_methods,
				      struct alist *methods,
				      struct alist *services)
{
  NEW(userauth_service, self);

  self->super.call = do_userauth;
  self->advertised_methods = advertised_methods;
  self->methods = methods;
  self->services = services;
  
  return &self->super;
}
