/* server_userauth.c
 *
 * Server side user authentication. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999 Niels Möller
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

#include "server_userauth.h"

#include "connection.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>
#include <assert.h>
#include <errno.h>


#define GABA_DEFINE
#include "server_userauth.h.x"
#undef GABA_DEFINE

#include "server_userauth.c.x"

struct lsh_string *
format_userauth_failure(struct int_list *methods,
					   int partial)
{
  return ssh_format("%c%A%c", SSH_MSG_USERAUTH_FAILURE, methods, partial);
}

struct lsh_string *
format_userauth_success(void)
{
  return ssh_format("%c", SSH_MSG_USERAUTH_SUCCESS);
}


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

      /* Serialize handling of userauth requests */
      connection_lock(connection);
      
      if (!(auth && service))
	{
	  static const struct exception userauth_failed
	    = STATIC_EXCEPTION(EXC_USERAUTH,
			       "Unknown auth method or service.");
	  
	  EXCEPTION_RAISE(closure->e, &userauth_failed);
	  return;
	}

      /* FIXME: Do the user_db lookup here? */
      AUTHENTICATE(auth, connection, user, requested_service, &buffer,
		   make_delay_continuation(service, closure->c),
		   closure->e);
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid USERAUTH message.");

  lsh_string_free(packet);
}

struct packet_handler *
make_userauth_handler(struct alist *methods,
                      struct alist *services,
                      struct command_continuation *c,
                      struct exception_handler *e)
{
  NEW(userauth_handler, auth);

  auth->super.handler = do_handle_userauth;
  auth->methods = methods;
  auth->services = services;
  auth->c = c;
  auth->e = e;

  return &auth->super;
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
 * I think the right thing to do is to serialize userauth requests
 * completely: if a request can't be replied to immediately, put the
 * entire connection on hold until the reply is ready.
 *
 * This code now uses serialization, using connection_lock() and
 * connection_unlock(). However, the implementation of serialization
 * is rather stupid. And will crash if a userauth method returns to
 * the main loop while the connection is still locked. */

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

  unsigned i;

  /* Access granted. */

  assert(action);

  /* Unlock connection */
  connection_unlock(self->connection);
  
  C_WRITE(self->connection, format_userauth_success());

  /* Ignore any further userauth messages. */
  for (i = SSH_FIRST_USERAUTH_GENERIC; i < SSH_FIRST_CONNECTION_GENERIC; i++) 
    self->connection->dispatch[i] = self->connection->ignore;
  
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
      {
	/* Unlock connection */
	connection_unlock(self->connection);

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
      }
    case EXC_USERAUTH_SPECIAL:
      {
	CAST_SUBTYPE(userauth_special_exception, e, x);

	/* Unlock connection */
	connection_unlock(self->connection);
	
	/* NOTE: We can't NULL e->reply, since the exception is supposed to be constant.
	 * So we have to dup it, to make the gc happy. */
	C_WRITE(self->connection, lsh_string_dup(e->reply));

	break;
      }
    }
}

struct exception_handler *
make_exc_userauth_handler(struct ssh_connection *connection,
			  struct int_list *advertised_methods,
			  unsigned attempts,
			  struct exception_handler *parent,
			  const char *context)
{
  NEW(exc_userauth_handler, self);
  self->super.raise = do_exc_userauth_handler;
  self->super.parent = parent;
  self->super.context = context;
  
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

  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] =
    make_userauth_handler(self->methods, self->services,
			  make_userauth_continuation(connection, c, e),
                          make_exc_userauth_handler(connection,
                                                    self->advertised_methods,
                                                    AUTH_ATTEMPTS, e,
                                                    HANDLER_CONTEXT));
}

struct command *
make_userauth_service(struct int_list *advertised_methods,
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
