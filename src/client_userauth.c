/* client_userauth.c
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "userauth.h"

#include "charset.h"
#include "format.h"
#include "parse.h"
#include "password.h"
#include "service.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

/* FIXME: For now, use only password authentication. A better method
 * would be to first send a set of publickey authentication requests
 * for the available keys (for some configurable value of
 * "available"). This is analogous to unlocking a door by first
 * examining the keys on one's keyring to see if any of them kan be
 * inserted into the lock. Preferably, at this point one should use
 * spki hashed public keys rather than the public keys themselves.
 *
 * Next we wait for SSH_MSH_USERAUTH_FAILURE or SSH_MSG_USERAUTH_PK_OK
 * messages. If any of the keys is recognized, we compute a signature
 * and send it to the server (analogously to inserting the key into
 * the lock and turning it around).
 *
 * If none of the keys were recognized, or if no keys were available
 *from the start, we ask the user for a password and attempts to log
 *in using that. */

struct client_userauth
{
  struct ssh_service super;

  struct lsh_string *username; /* Remote user name to authenticate as */
  int service_name;   /* Service we want to access */
  struct ssh_service *service;
  
  /* FIXME: Keys to try */
};

struct success_handler
{
  struct packet_handler super;

  struct ssh_service *service;
};

struct failure_handler
{
  struct packet_handler super;

  struct client_userauth *userauth;
};

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

#define MAX_PASSWD 100

static int send_passwd(struct client_userauth *userauth,
		       struct ssh_connection *connection)
{
  struct lsh_string *passwd
    = read_password(MAX_PASSWD, ssh_format("Password for %lS: ",
					   userauth->username));
  
  if (!passwd)
    return LSH_FAIL | LSH_DIE;
  
  return A_WRITE(connection->write,
		 format_userauth_password(local_to_utf8(userauth->username, 0),
					  userauth->service_name,
					  local_to_utf8(passwd, 1),
					  1));
}

static int do_userauth_success(struct packet_handler *c,
				struct ssh_connection *connection,
				struct lsh_string *packet)
{
  struct success_handler *closure = (struct success_handler *) c;
  struct simple_buffer buffer;

  int msg_number;
    
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_SUCCESS)
      && parse_eod(&buffer))
    {
      werror("User authentication successful.\n");

      lsh_string_free(packet);
      
      connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = connection->fail;
      connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = connection->fail;
      connection->dispatch[SSH_MSG_USERAUTH_BANNER] = connection->fail;
      
      return SERVICE_INIT(closure->service, connection);
    }
  
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_userauth_failure(struct packet_handler *c,
			       struct ssh_connection *connection,
			       struct lsh_string *packet)
{
  struct failure_handler *closure = (struct failure_handler *) c;
  struct simple_buffer buffer;

  int msg_number;
  int *methods = NULL;
  int partial_success;
    
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_FAILURE)
      && ( (methods = parse_atom_list(&buffer)) )
      && parse_boolean(&buffer, &partial_success)
      && parse_eod(&buffer))
    {
      int i;
      
      lsh_string_free(packet);

      if (partial_success)
	{ /* Doesn't help us */
	  werror("Recieved SSH_MSH_USERAUTH_FAILURE "
		 "indicating partial success.\n");
	  lsh_free(methods);

	  return LSH_FAIL | LSH_DIE;
	}
      for(i = 0; methods[i] >= 0; i++)
	if (methods[i] == ATOM_PASSWORD)
	  {
	    /* Try again */
	    lsh_free(methods);
	    return send_passwd(closure->userauth, connection);
	  }
      /* No methods that we can use */
      lsh_free(methods);
      return LSH_FAIL | LSH_DIE;
    }

  if (methods)
    lsh_free(methods);
  
  lsh_string_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static int do_userauth_banner(struct packet_handler *closure,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct simple_buffer buffer;

  int msg_number;
  UINT32 length;
  UINT8 *msg;

  UINT32 language_length;
  UINT8 *language;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_BANNER)
      && parse_string(&buffer, &length, &msg)
      && parse_string(&buffer, &language_length, &language)
      && parse_eod(&buffer))
    {
      /* Ignore language tag */
      werror_utf8(length, msg);

      lsh_string_free(packet);
      return LSH_OK | LSH_GOON;
    }
  lsh_free(packet);
  return LSH_FAIL | LSH_DIE;
}

static struct packet_handler *make_success_handler(struct ssh_service *service)
{
  struct success_handler *self;

  NEW(self);
  self->super.handler = do_userauth_success;
  self->service = service;

  return &self->super;
}

static struct packet_handler *
make_failure_handler(struct client_userauth *userauth)
{
  struct failure_handler *self;

  NEW(self);
  self->super.handler = do_userauth_failure;
  self->userauth = userauth;

  return &self->super;
}

static struct packet_handler *make_banner_handler()
{
  struct packet_handler *self;

  NEW(self);
  self->handler = do_userauth_banner;
  
  return self;
}

static int init_client_userauth(struct ssh_service *c,
				struct ssh_connection *connection)
{
  struct client_userauth *closure = (struct client_userauth *) c;

  MDEBUG(closure);

  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS]
    = make_success_handler(closure->service);
  connection->dispatch[SSH_MSG_USERAUTH_FAILURE]
    = make_failure_handler(closure);
  connection->dispatch[SSH_MSG_USERAUTH_BANNER]
    = make_banner_handler();

  return send_passwd(closure, connection);
}

struct ssh_service *make_client_userauth(struct lsh_string *username,
					 int service_name,
					 struct ssh_service *service)
{
  struct client_userauth *closure;

  NEW(closure);

  closure->super.init = init_client_userauth;
  closure->username = username;
  closure->service_name = service_name;
  closure->service = service;

  return &closure->super;
}
