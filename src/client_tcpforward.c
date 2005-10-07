/* client_tcpforward.c
 *
 * Client side of tcpip forwarding.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Balázs Scheidler, Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "tcpforward.h"

#include "channel_forward.h"
#include "io_commands.h"
#include "ssh.h"
#include "werror.h"

/* Forward declarations */
/* FIXME: Should be static */
struct command_3 open_direct_tcpip_command;
#define OPEN_DIRECT_TCPIP (&open_direct_tcpip_command.super.super)

#include "client_tcpforward.c.x"


/* Local forwarding using direct-tcpip */

/* (open_direct_tcpip target connection listen_value) */
DEFINE_COMMAND3(open_direct_tcpip_command)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct lsh_object *a3,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST(address_info, target, a1);
  CAST_SUBTYPE(ssh_connection, connection, a2);
  CAST(listen_value, lv, a3);

  struct channel_forward *channel;

  trace("open_direct_tcpip_command\n");

  io_register_fd(lv->fd, "forwarded socket");
  channel = make_channel_forward(lv->fd, TCPIP_WINDOW_SIZE);
  
  if (!channel_open_new_type(connection, &channel->super, ATOM_DIRECT_TCPIP,
			     "%S%i%S%i",
			     target->ip, target->port,
			     lv->peer->ip, lv->peer->port))
			     
    {
      EXCEPTION_RAISE(e, make_exception(EXC_CHANNEL_OPEN, SSH_OPEN_RESOURCE_SHORTAGE,
					"Allocating a local channel number failed."));
      KILL_RESOURCE(&channel->super.super);
    }
  else
    {
      assert(!channel->super.channel_open_context);
      channel->super.channel_open_context = make_command_context(c, e);
    }
}

/* GABA:
   (expr
     (name forward_local_port)
     (params
       (local object address_info)
       (target object address_info))
     (expr
       (lambda (connection)
         (connection_remember connection
           (listen_tcp
	     (lambda (peer)
	       (open_direct_tcpip target connection peer))
	       
	     ; NOTE: The use of prog1 is needed to delay the
	     ; listen_tcp call until the (otherwise ignored)
	     ; connection argument is available.
	     (prog1 local connection))))))
*/

