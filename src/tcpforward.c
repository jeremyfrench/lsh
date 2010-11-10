/* tcpforward.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005, 2008 Balázs Scheidler, Niels Möller
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
#include "io.h"
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

struct forwarded_port *
tcpforward_remove(struct object_queue *q,
		  uint32_t length, const uint8_t *ip, uint32_t port)
{
  FOR_OBJECT_QUEUE(q, n)
    {
      CAST_SUBTYPE(forwarded_port, p, n);

      if ( (port == p->address->port)
	   && lsh_string_eq_l(p->address->ip, length, ip) )
	{
	  FOR_OBJECT_QUEUE_REMOVE(q, n);
	  return p;
	}
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
     (name tcpforward_listen_port)
     (super io_listen_port)
     (vars
       (type . int)
       (connection object ssh_connection)
       (forward const object address_info)))       
*/

static void
do_tcpforward_listen_port_accept(struct io_listen_port *s,
				 int fd,
				 socklen_t addr_length,
				 const struct sockaddr *addr)  
{
  CAST(tcpforward_listen_port, self, s);

  struct channel_forward *channel;
  struct address_info *peer = sockaddr2info(addr_length, addr);
  trace("forward_local_port\n");

  io_register_fd(fd, "forwarded socket");
  channel = make_channel_forward(fd, TCPIP_WINDOW_SIZE);

  if (!channel_open_new_type(self->connection, &channel->super,
			     ATOM_LD(self->type),
			     "%S%i%S%i",
			     self->forward->ip, self->forward->port,
			     peer->ip, peer->port))
    {
      werror("tcpforward_listen_port: Allocating a local channel number failed.");
      KILL_RESOURCE(&channel->super.super);
    }
}

/* Like in the protocol (RFC 4254), empty address means listen on all
   interfaces. */
struct resource *
tcpforward_listen(struct ssh_connection *connection,
		  int type,
		  const struct address_info *local,
		  const struct address_info *forward)
{
  struct addrinfo *list;
  struct addrinfo *p;
  int err;

  struct resource_list *resources;

  trace("tcpforward_listen: Local port: %S:%i, target port: %S:%i\n",
	local->ip, local->port, forward->ip, forward->port);

  err = io_getaddrinfo(local, AI_PASSIVE, &list);
  if (err)
    {
      if (err == EAI_SYSTEM)
	werror("tcpforward_listen: getaddrinfo failed: %e\n", errno);
      else
	werror("tcpforward_listen: getaddrinfo failed: %z\n",
	       gai_strerror(err));
      return NULL;
    }

  resources = NULL;

  for (p = list; p; p = p->ai_next)
    if (p->ai_family == AF_INET || p->ai_family == AF_INET6)
      {
	int fd = io_bind_sockaddr(p->ai_addr, p->ai_addrlen);
	if (fd >= 0)
	  {
	    NEW(tcpforward_listen_port, self);
	    init_io_listen_port(&self->super, fd,
				do_tcpforward_listen_port_accept);

	    self->connection = connection;
	    self->type = type;
	    self->forward = forward;

	    if (!io_listen(&self->super))
	      KILL_RESOURCE(&self->super.super.super);
	    else
	      {
		struct address_info *bound
		  = sockaddr2info(p->ai_addrlen, p->ai_addr);

		trace("tcpforward_listen: Bound port %S:%i\n",
		      bound->ip, bound->port);

		KILL(bound);

		if (!resources)
		  resources = make_resource_list();

		remember_resource(resources, &self->super.super.super);
	      }
	  }
      }

  freeaddrinfo(list);

  return &resources->super;
}

/* GABA:
   (class
     (name tcpforward_connect_state)
     (super io_connect_state)
     (vars
       ; List of addresses to try
       (list special "struct addrinfo *" #f freeaddrinfo)
       (next . "struct addrinfo *")
       
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

  for (; self->next; self->next = self->next->ai_next)
    {
      verbose("Connection failed, trying next address.\n");
      io_close_fd(self->super.super.fd);
      self->super.super.fd = -1;
      if (io_connect(&self->super, self->next->ai_addrlen, self->next->ai_addr))
	return;
    }
  werror("Connection failed: %e\n", error);
  channel_open_deny(self->info,
		    SSH_OPEN_CONNECT_FAILED, "Connection failed");
}

struct resource *
tcpforward_connect(const struct address_info *addr,
		   const struct channel_open_info *info)
{
  struct addrinfo *list;
  int err;

  trace("tcpforward_connect: target port: %S:%i\n",
	addr->ip, addr->port);
  
  /* FIXME: Use AI_ADDRCONFIG ? */
  err = io_getaddrinfo(addr, 0, &list);
  if (err)
    {
      werror("Could not resolv address `%S:%i\n",
	     addr->ip, addr->port, gai_strerror(err));
      channel_open_deny(info, SSH_OPEN_CONNECT_FAILED,
			"Address could not be resolved.");
      return NULL;
    }
  else
    {
      NEW(tcpforward_connect_state, self);

      init_io_connect_state(&self->super,
			    tcpforward_connect_done,
			    tcpforward_connect_error);
      self->info = info;
      self->list = list; 
     
      for (self->next = self->list; self->next; self->next = self->next->ai_next)
	{
	  if (io_connect(&self->super,
			 self->next->ai_addrlen, self->next->ai_addr))
	    return &self->super.super.super;
	}

      channel_open_deny(info, SSH_OPEN_CONNECT_FAILED, STRERROR(errno));
      return NULL;
    }
}
