/* proxy_userauth.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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

#include "proxy_userauth.h"
#include "proxy.h"
#include "server_userauth.h"
#include "client_userauth.h"
#include "xalloc.h"
#include "ssh.h"
#include "lsh.h"
#include "werror.h"

#define GABA_DEFINE
#include "proxy_userauth.h.x"
#undef GABA_DEFINE

#include "proxy_userauth.c.x"

static struct proxy_user *
make_proxy_user(struct lsh_string *name)
{
  NEW(proxy_user, self);
  self->name = name;
  return self;
}

/* GABA:
   (class
     (name proxy_userauth_success)
     (super packet_handler)
     (vars
       (name string)
       (c object command_continuation)))
*/

static void
do_forward_success(struct packet_handler *c,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  CAST(proxy_userauth_success, self, c);

  struct simple_buffer buffer;
  unsigned msg_number;

  simple_buffer_init(&buffer, packet->length, packet->data);

  connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = connection->fail;

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_SUCCESS)
      && parse_eod(&buffer))
    {
      C_WRITE(connection->chain, packet);
      COMMAND_RETURN(self->c, make_proxy_user(self->name));
    }
  else
    {
      PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_USERAUTH_SUCCESS message.");
      lsh_string_free(packet);
    }
}


static struct packet_handler *
make_forward_success(struct lsh_string *name, 
		     struct command_continuation *c)
{
  NEW(proxy_userauth_success, self);
  self->super.handler = do_forward_success;
  self->name = name;
  self->c = c;
  return &self->super;
}

/* GABA:
   (class
     (name proxy_userauth_failure)
     (super packet_handler)
     (vars
       (e object exception_handler)))
*/


static void
do_forward_failure(struct packet_handler *c UNUSED,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  simple_buffer_init(&buffer, packet->length, packet->data);

  connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = connection->fail;

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_USERAUTH_SUCCESS)
      && parse_eod(&buffer))
    {
      verbose("Authentication failure");
      C_WRITE(connection->chain, packet);
    }
  else
    {
      PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_USERAUTH_SUCCESS message.");
      lsh_string_free(packet);
    }
}

static struct packet_handler *
make_forward_failure(struct exception_handler *e)
{
  NEW(proxy_userauth_failure, self);
  self->super.handler = do_forward_failure;
  self->e = e;
  return &self->super;
}

/* ;; GABA:
   (class
     (name proxy_userauth)
     (super userauth)
     (vars
*/

static void
do_forward_userauth_req(struct userauth *ignored UNUSED,
			struct ssh_connection *connection,
			struct lsh_string *username,
			UINT32 service,
			struct simple_buffer *args,
			struct command_continuation *c UNUSED,
			struct exception_handler *e UNUSED)
{
  struct lsh_string *password;
  int change_password;

  if (parse_boolean(args, &change_password) &&
      (password = parse_string_copy(args)) &&
      parse_eod(args))
    {

      connection->chain->dispatch[SSH_MSG_USERAUTH_FAILURE] = 
	make_forward_failure(e);	

      connection->chain->dispatch[SSH_MSG_USERAUTH_SUCCESS] =
	make_forward_success(username, c);

      C_WRITE(connection->chain, format_userauth_password(username, service, password, 1));
    }
}

struct userauth proxy_password_auth =
{ STATIC_HEADER, do_forward_userauth_req };

static void
do_userauth_proxy(struct command *s,
		  struct lsh_object *x, 
		  struct command_continuation *c,
		  struct exception_handler *e)
{
  CAST(userauth_service, self, s);
  CAST(ssh_connection, connection, x);

  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] =
    make_userauth_handler(self->methods,
			  self->services, 
			  c,
			  e);
}

struct command *
make_userauth_proxy(struct int_list *allowed_methods,
		    struct alist *methods,
		    struct alist *services)
{
  NEW(userauth_service, self);

  self->super.call = do_userauth_proxy;
  self->advertised_methods = allowed_methods;
  self->methods = methods;
  self->services = services;
  return &self->super;
}

