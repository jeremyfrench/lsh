/* server.c
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include "server.h"

#include "abstract_io.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "sexp.h"
#include "spki.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#if 0
#include "server.c.x"


static struct lsh_string *
format_service_accept(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_ACCEPT, name);
}


/* GABA:
   (class
     (name service_handler)
     (super packet_handler)
     (vars
       (services object alist)
       (c object command_continuation)
       (e object exception_handler)))
*/

static void
do_service_request(struct packet_handler *c,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  CAST(service_handler, closure, c);

  struct simple_buffer buffer;
  unsigned msg_number;
  int name;
  
  simple_buffer_init(&buffer, STRING_LD(packet));

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_eod(&buffer))
    {
      if (name)
	{
	  CAST_SUBTYPE(command, service, ALIST_GET(closure->services, name));
	  if (service)
	    {
	      /* Don't accept any further service requests */
	      connection->dispatch[SSH_MSG_SERVICE_REQUEST]
		= &connection_fail_handler;

	      /* Start service */
	      connection_send(connection, format_service_accept(name));
	      
	      COMMAND_CALL(service, connection,
			   closure->c, closure->e);
	      return;
	    }
	}
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, NULL));
      
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid SERVICE_REQUEST message");
}

static struct packet_handler *
make_service_request_handler(struct alist *services,
			     struct command_continuation *c,
			     struct exception_handler *e)
{
  NEW(service_handler, self);

  self->super.handler = do_service_request;
  self->services = services;
  self->c = c;
  self->e = e;
  
  return &self->super;
}

     
/* GABA:
   (class
     (name offer_service)
     (super command)
     (vars
       (services object alist)))
*/

static void
do_offer_service(struct command *s,
		 struct lsh_object *x,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  CAST(offer_service, self, s);
  CAST(ssh_connection, connection, x);

  connection->dispatch[SSH_MSG_SERVICE_REQUEST]
    = make_service_request_handler(self->services, c, e);
}

struct command *make_offer_service(struct alist *services)
{
  NEW(offer_service, self);

  self->super.call = do_offer_service;
  self->services = services;

  return &self->super;
}
#endif

/* Read server's private key */

static void
add_key(struct alist *keys,
        struct keypair *key)
{
  if (ALIST_GET(keys, key->type))
    werror("Multiple host keys for algorithm %a\n", key->type);
  ALIST_SET(keys, key->type, &key->super);
}

int
read_host_key(const char *file,
              struct alist *signature_algorithms,
              struct alist *keys)
{
  int fd = open(file, O_RDONLY);
  struct lsh_string *contents;
  struct signer *s;
  struct verifier *v;
  
  int algorithm_name;

  if (fd < 0)
    {
      werror("Failed to open `%z' for reading %e\n", file, errno);
      return 0;
    }
  
  contents = io_read_file_raw(fd, 5000);
  if (!contents)
    {
      werror("Failed to read host key file `%z': %e\n", file, errno);
      close(fd);
      return 0;
    }
  close(fd);

  s = spki_make_signer(signature_algorithms,
		       contents,
		       &algorithm_name);
  lsh_string_free(contents);
  
  if (!s)
    {
      werror("Invalid host key\n");
      return 0;
    }

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  switch (algorithm_name)
    {
    case ATOM_DSA:
      add_key(keys,
              make_keypair(ATOM_SSH_DSS, PUBLIC_KEY(v), s));
      break;

    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      add_key(keys,
              make_keypair(ATOM_SSH_RSA, PUBLIC_KEY(v), s));
      break;

    default:
      werror("read_host_key: Unexpected algorithm %a.\n", algorithm_name);
    }
  return 1;
}
