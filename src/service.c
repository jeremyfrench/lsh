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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "service.h"

#include "disconnect.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "xalloc.h"

#if 0
#define GABA_DEFINE
#include "service.h.x"
#undef GABA_DEFINE

#include "service.c.x" 
#endif

/* ;;GABA:
   (class
     (name service_handler)
     (super packet_handler)
     (vars
       (services object alist)))
*/

struct lsh_string *format_service_request(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_REQUEST, name);
}

struct lsh_string *format_service_accept(int name)
{
  return ssh_format("%c%a", SSH_MSG_SERVICE_ACCEPT, name);
}

/* ;;GABA:
   (class
     (name meta_service)
     (super ssh_service)
     (vars
       (service_handler object packet_handler)))
*/
#if 0
static int init_meta_service(struct ssh_service *c,
			     struct ssh_connection *connection)
{
  CAST(meta_service, closure, c);

  connection->dispatch[SSH_MSG_SERVICE_REQUEST] = closure->service_handler;

  return LSH_OK | LSH_GOON;
}
  
struct ssh_service *make_meta_service(struct alist *services)
{
  NEW(meta_service, self);

  self->super.init = init_meta_service;
  self->service_handler = make_service_handler(services);

  return &self->super;
}
#endif
