/* tcpforward.c
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
#include <string.h>

#include "tcpforward.h"

#include "channel_forward.h"
#include "format.h"
#include "io_commands.h"
#include "lsh_string.h"
#include "ssh.h"

#include "werror.h"


#define GABA_DEFINE
#include "tcpforward.h.x"
#undef GABA_DEFINE

#include "tcpforward.c.x"

/* Structures used to keep track of forwarded ports */

struct forwarded_port *
tcpforward_lookup(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST_SUBTYPE(forwarded_port, f, n);
      
      if ( (port == f->address->port)
	   && lsh_string_eq_l(f->address->ip, length, ip) )
	return f;
    }
  return NULL;
}

int
tcpforward_remove_port(struct object_queue *q, struct forwarded_port *port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST_SUBTYPE(forwarded_port, f, n);
      
      if (port == f)
	{
	  FOR_OBJECT_QUEUE_REMOVE(q, n);
	  return 1;
	}
    }
  return 0;
}

/* GABA:
   (class
     (name tcpforward_connect_state)
     (super io_connect_state)
     (vars
       (info const object channel_open_info)))
*/

static void
tcpforward_connect_done(struct io_connect_state *s, int fd)
{
  CAST(tcpforward_connect_state, self, s);

  struct channel_forward *channel
    = make_channel_forward(fd, TCPIP_WINDOW_SIZE);
  
  channel_open_confirm(self->info, &channel->super);
  channel_forward_start_io(channel);  
}

static void
tcpforward_connect_error(struct io_connect_state *s, int error)
{
  CAST(tcpforward_connect_state, self, s);
  
  werror("Connection failed, socket error %i\n", error);
  channel_open_deny(self->info,
		    SSH_OPEN_CONNECT_FAILED, "Connection failed");
}

struct resource *
tcpforward_connect(struct address_info *a,
		   const struct channel_open_info *info)
{
  struct sockaddr *addr;
  socklen_t addr_length;

  addr = io_make_sockaddr(&addr_length, lsh_get_cstring(a->ip), a->port);
  if (!addr)
    {
      channel_open_deny(info, SSH_OPEN_CONNECT_FAILED, "Invalid address");
      return NULL;
    }

  {
    NEW(tcpforward_connect_state, self);
    init_io_connect_state(&self->super,
			  tcpforward_connect_done,
			  tcpforward_connect_error);
    int res;
    
    self->info = info;

    res = io_connect(&self->super, addr_length, addr);
    lsh_space_free(addr);

    if (!res)
      {
	channel_open_deny(info, SSH_OPEN_CONNECT_FAILED, STRERROR(res));
	return NULL;
      }
    return &self->super.super;
  }
}
