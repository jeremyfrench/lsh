/* server_userauth.c
 *
 * Server side user authentication. */

#include "service.h"
#include "userauth.h"

/* FIXME: Supports only password authentication so far. There should
 * be some abstraction for handling several authentication methods. */

struct userauth_service
{
  struct service super;

  struct alist *methods; /* Maps authentication method names to methods */
};

/* Max number of attempts */
#define AUTH_ATTEMPTS 20

/* FIXME: There are no timeouts for authentications. The callouts in
 * io.c could be used for timeouts, but it's not clear how the timeout
 * handler can close the right connection. */

struct userauth_handler
{
  struct packet_handler super;

  /* Attempts left */  
  int attempts;

  /* Methods advertised in failure messages */
  int *advertised_methods;
  
  struct alist *methods;
};

struct lsh_string *format_userauth_failure(int *methods, int partial)
{
  return ssh_format("%c%A%c", SSH_MSG_USERAUTH_FAILURE, methods, partial);
}

struct lsh_string *format_userauth_success()
{
  return ssh_format("%c", SSH_MSG_USERAUTH_SUCCESS);
}

/* NOTE: This implementation does not use any partial successes. As
 * soon as one authentication request is successful, the
 * entire authentication process succeeds. */
static int do_handle_user_auth(struct packet_handler *c,
			       struct ssh_connection *connection,
			       struct lsh_string *packet)
{
  struct userauth_handler * closure = (struct userauth_handler *) c;
  struct simple_buffer buffer;

  int msg_number;
  struct lsh_string *user;
  int requested_service;
  int method;
    
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_REQUEST)
      && parse_string_copy(&buffer, &user)
      && parse_atom(&buffer, &requested_service)
      && parse_atom(&buffer, &method))
    {
      struct ssh_service *service;
      self->attempts--;

      struct userauth *auth = ALIST_GET(closure->methods, method);
      if (!auth)
	return attempts
	  ? A_WRITE(connection->write,
		    format_userauth_failure(self->advertised_methods,
					    0))
	  : LSH_FAIL | LSH_DIE;
      
      if (AUTHENTICATE(auth, user, requested_service,
		       &buffer, &service))
	{
	  if (service
	      && SERVICE_INIT(service, connection))
	    /* Access granted */
	    return A_WRITE(connection->write, format_userauth_success());
	  else
	    return attempts
	      ? A_WRITE(connection->write,
			format_userauth_failure(self->advertised_methods,
						0))
	      : LSH_FAIL | LSH_DIE;
	}
    }
  /* Invalid request */
  return LSH_FAIL | LSH_DIE;
}

static int init_userauth(struct service *s, int name, struct ssh_connection *c)
{
  struct userauth_service *self = (struct userauth_service *) s;
  struct userauth_handler *auth; = xalloc(sizeof(struct userauth_handler));
  
  MDEBUG(self);

  auth->super.handler = do_handle_userauth;
  auth->methods = self->methods;
  auth->attempts = AUTH_ATTEMPTS;
  
  c->dispatch[SSH_MSG_USERAUTH_REQUEST] = &auth->super;

  return 1;
}

struct ssh_service *make_userauth_service(struct alist *methods)
{
  struct userauth_service *self = xalloc(sizeof(struct userauth_service));

  self->super.init = init_userauth;
  self->methods = methods;
  
  return &self->super;
}
  
