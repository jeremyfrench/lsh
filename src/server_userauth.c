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
 * handler can close the right connection. */

/* NOTE: Here we assume that services and authentication methods are
 * orthogonal. I.e. every supported authentication method is accepted
 * for every supported service. */

/* GABA:
   (class
     (name userauth_handler)
     (super packet_handler)
     (vars
       ; Attempts left 
       (attempts simple int)

       ; What to do after successful authentication
       (c object command_continuation)
       (e object exception_handler)
       
       ; Methods advertised in failure messages
       (advertised_methods object int_list)

       ; Maps authentication methods to userath objects
       (methods object alist)

       ; Maps services to commands
       (services object alist)))
*/

struct lsh_string *format_userauth_failure(struct int_list *methods,
					   int partial)
{
  return ssh_format("%c%A%c", SSH_MSG_USERAUTH_FAILURE, methods, partial);
}

struct lsh_string *format_userauth_success(void)
{
  return ssh_format("%c", SSH_MSG_USERAUTH_SUCCESS);
}

/* FIXME: Perhaps this should use a two-dimensional lookup, and call
 * an authentication object depending on both service and method? */

/* NOTE: This implementation does not use any partial successes. As
 * soon as one authentication request is successful, the
 * entire authentication process succeeds. */
static int do_handle_userauth(struct packet_handler *c,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  CAST(userauth_handler,  closure, c);
  struct simple_buffer buffer;

  unsigned msg_number;
  struct lsh_string *user;
  int requested_service;
  int method;
  int res;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_REQUEST)
      && ( (user = parse_string_copy(&buffer)) )
      && parse_atom(&buffer, &requested_service)
      && parse_atom(&buffer, &method))
    {
      struct lsh_object *auth_info = NULL;
      
      CAST_SUBTYPE(userauth, auth, ALIST_GET(closure->methods, method));
      CAST_SUBTYPE(command, service,
		   ALIST_GET(closure->services, requested_service));
      
      lsh_string_free(packet);
      
      closure->attempts--;

      if (!(auth && service))
	return closure->attempts
	  ? A_WRITE(connection->write,
		    format_userauth_failure(closure->advertised_methods,
					    0))
	  : LSH_FAIL | LSH_DIE;

      res = AUTHENTICATE(auth, user, &buffer, &auth_info);

      if (LSH_CLOSEDP(res))
	return res;
      
      if (res & LSH_AUTH_FAILED)
	{
	  return res
	    | (closure->attempts
	       ? A_WRITE(connection->write,
			 format_userauth_failure(closure->advertised_methods,
						 0))
	       /* FIXME: Send a disconnect message */
	       : LSH_FAIL | LSH_DIE);
	}

      /* Access granted */
      /* Ignore any further userauth messages. */
      connection->dispatch[SSH_MSG_USERAUTH_REQUEST]
	= connection->ignore;
      
      res |= A_WRITE(connection->write, format_userauth_success());

      if (LSH_CLOSEDP(res))
	return res;
      
      return res | COMMAND_CALL(service, auth_info, closure->c, closure->e);
    }

  /* Invalid request */
  lsh_string_free(packet);

  return LSH_FAIL | LSH_DIE;
}

static int do_userauth(struct command *s, 
		       struct lsh_object *x,
		       struct command_continuation *c,
		       struct exception_handler *e)
{
  CAST(userauth_service, self, s);
  CAST(ssh_connection, connection, x);
  NEW(userauth_handler, auth);
  
  auth->super.handler = do_handle_userauth;
  auth->advertised_methods = self->advertised_methods;
  auth->methods = self->methods;
  auth->services = self->services;
  auth->attempts = AUTH_ATTEMPTS;
  auth->c = c;
  auth->e = e;
  
  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] = &auth->super;

  return 1;
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
