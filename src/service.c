/* service.c
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

#include "service.h"
#include "format.h"

struct service_handler
{
  struct packet_handler super;
  struct alist *services;
};

struct lsh_string *format_service_accept(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_ACCEPT, name);
}

static int do_service(struct packet_handler *c,
		      struct ssh_connection *connection,
		      struct lsh_string *packet)
{
  struct service_handler *closure = (struct service_handler *) c;

  struct simple_buffer buffer;
  UINT8 msg_number;
  int name;
  
  MDEBUG(closure);

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_SERVICE_REQUEST)
      && parse_atom(&buffer, &name)
      && parse_eod(&buffer))
    {
      struct ssh_service *service;

      if (!name
	  || !(service = ALIST_GET(closure->services, name))
	  || !SERVICE_INIT(service, connection))
	{
	  int res
	    = A_WRITE(c->write,
		      format_disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
					"Service not available.\n"));
	  return (LSH_PROBLEMP(res)
		  ? LSH_FAIL | LSH_DIE
		  : LSH_FAIL | LSH_CLOSE);
	}
      /* Don't accept any further service requests */
      connection->dispatch[SSH_SERVICE_REQUEST]
	= connection->fail;
      
      return A_WRITE(c->write(format_service_accept(name)));
    }
  return LSH_FAIL | LSH_DIE;
}
      
struct packet_handler *make_service_handler(struct alist *services)
{
  struct service_handler *self = xalloc(sizeof(struct service_handler));

  self->super.handler = do_service;
  self->services = services;

  return &self->super;
}
