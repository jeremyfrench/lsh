/* service.c
 *
 * $Id$
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

#include "service.h"

#include "disconnect.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "xalloc.h"

#define CLASS_DEFINE
#include "service.h.x"
#undef CLASS_DEFINE

#include "service.c.x"

/* CLASS:
   (class
     (name service_handler)
     (super packet_handler)
     (vars
       (object alist services)))
*/

#if 0
struct service_handler
{
  struct packet_handler super;
  struct alist *services;
};
#endif


struct lsh_string *format_service_request(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_REQUEST, name);
}

struct lsh_string *format_service_accept(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_ACCEPT, name);
}

static int do_service(struct packet_handler *c,
		      struct ssh_connection *connection,
		      struct lsh_string *packet)
{
  CAST(service_handler, closure, c);

  struct simple_buffer buffer;
  int msg_number;
  int name;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_eod(&buffer))
    {
      struct ssh_service *service;

      lsh_string_free(packet);
      
      if (!name
	  || !(service = ALIST_GET(closure->services, name))
	  || !SERVICE_INIT(service, connection))
	{
	  return (LSH_FAIL | LSH_CLOSE)
	    | A_WRITE(connection->write,
		      format_disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
					"Service not available.", ""));
	}
      /* Don't accept any further service requests */
      connection->dispatch[SSH_MSG_SERVICE_REQUEST]
	= connection->fail;
      
      return A_WRITE(connection->write, format_service_accept(name));
    }
  return LSH_FAIL | LSH_DIE;
}
      
struct packet_handler *make_service_handler(struct alist *services)
{
  struct service_handler *self;

  NEW(self);

  self->super.handler = do_service;
  self->services = services;

  return &self->super;
}

/* CLASS:
   (class
     (name meta_service)
     (super ssh_service)
     (vars
       (object packet_handler service_handler)))
*/

#if 0
struct meta_service
{
  struct ssh_service super;

  struct packet_handler *service_handler;
};
#endif

static int init_meta_service(struct ssh_service *c,
			     struct ssh_connection *connection)
{
  CAST(meta_service, closure, c);

  MDEBUG(closure);
  
  connection->dispatch[SSH_MSG_SERVICE_REQUEST] = closure->service_handler;

  return LSH_OK | LSH_GOON;
}
  
struct ssh_service *make_meta_service(struct alist *services)
{
  struct meta_service *self;

  NEW(self);

  self->super.init = init_meta_service;
  self->service_handler = make_service_handler(services);

  return &self->super;
}
