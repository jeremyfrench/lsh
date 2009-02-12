/* socks.c
 *
 * References:
 *
 * Socks4 is described in http://archive.socks.permeo.com/protocol/socks4.protocol.
 * Socks5 is described in RFC 1928.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2004, 2008 Niels Möller
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
#include <stdlib.h>
#include <string.h>

#include "nettle/macros.h"
#include "channel_forward.h"
#include "client.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "ssh.h"
#include "tcpforward.h"
#include "werror.h"
#include "xalloc.h"

/* Various protocol constants */
enum {
  /* Version exchange */
  SOCKS_NOAUTH = 0,
  SOCKS_NOMETHOD = 0xff,
};

/* Commands */
enum {
  SOCKS_CONNECT = 1,
  SOCKS_BIND = 2,
  SOCKS_UDP = 3,
};

/* Addresses */
enum {
  SOCKS_IP4 = 1,
  SOCKS_DNS = 3,
  SOCKS_IP6 = 4,
};

/* Status codes */
enum {
  SOCKS_ERROR_NONE = 0,
  SOCKS_ERROR_GENERAL = 1,
  SOCKS_ERROR_NOT_ALLOWED = 2,
  SOCKS_ERROR_NET_UNREACHABLE = 3,
  SOCKS_ERROR_HOST_UNREACHABLE = 4,
  SOCKS_ERROR_CONNECTION_REFUSED = 5,
  SOCKS_ERROR_TTL_EXPIRED = 6,
  SOCKS_ERROR_COMMAND = 7,
  SOCKS_ERROR_ADDRESS = 8,
};

/* Message sizes. */
enum {
  SOCKS_HEADER_SIZE = 2,
  SOCKS_COMMAND_SIZE = 5,
  SOCKS4_COMMAND_SIZE = 9, /* FIXME: For now we support only empty usernames */
  /* Maximum size is a request with a 256 byte DNS address, 262 bytes
     in all. THe maximum size for a reply is the same. */
  SOCKS_MAX_SIZE = 262
};

enum socks_state {
  /* Initial version header */
  SOCKS_VERSION_HEADER,
  /* SOCKS5 method list */
  SOCKS_VERSION_METHODS,
  /* SOCKS5 command, header and body. */
  SOCKS_COMMAND_HEADER, SOCKS_COMMAND_ADDR,
  /* SOCKS4 command */
  SOCKS4_COMMAND,
  /* Waiting for ssh CHANNEL_OPEN. */
  SOCKS_COMMAND_WAIT,
  /* Waiting for an error reply to be written, before closing. */
  SOCKS_CLOSE
};

#include "socks.c.x"

static const uint8_t ip4_noaddr[4] = {0,0,0,0};

#define SOCKS_NOADDR SOCKS_IP4, sizeof(ip4_noaddr), ip4_noaddr

/* Forward declarations */
static void
socks_start_write(struct socks_channel *self);

static void
socks_stop_write(struct socks_channel *self);

static void
socks_start_read(struct socks_channel *self);

static void
socks_stop_read(struct socks_channel *self);


/* GABA:
   (class
     (name socks_channel)
     (super channel_forward)
     (vars
       ; We use the channel's read and write buffers for the socks
       ; handshake.

       ; The write position (i.e. the amount of data) in the read buffer
       (pos . uint32_t)
       ; How much data we need before processing
       (length . uint32_t)
       
       (peer object address_info)
       (state . "enum socks_state")
       
       (version . uint8_t)
       (target object address_info)))
*/

static void
socks_close(struct socks_channel *self)
{
  self->state = SOCKS_CLOSE;
  if (self->super.write.state->length)
    global_oop_source->cancel_fd(global_oop_source, self->super.read.fd, OOP_READ);
  else
    KILL_RESOURCE(&self->super.super.super);
}

static void
socks_fail(struct socks_channel *self)
{
  KILL_RESOURCE(&self->super.super.super);
}

static void
socks_write(struct socks_channel *self, struct lsh_string *data)
{
  uint32_t done = ssh_write_data(self->super.write.state, self->super.write.fd,
				 0, STRING_LD(data));

  lsh_string_free(data);

  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (self->super.write.state->length > 0)
	socks_start_write(self);
      else
	socks_stop_write(self);
    }
  else
    {
      werror("socks server: write failed: %e.\n", errno);
      socks_fail(self);      
    }
}

static void *
oop_write_socks(oop_source *source UNUSED,
		int fd, oop_event event, void *state)
{
  CAST(socks_channel, self, state);
  
  assert(event == OOP_WRITE);
  assert(fd == self->super.write.fd);

  if (!ssh_write_flush(self->super.write.state, self->super.write.fd, 0))
    {
      werror("socks server: write failed: %e.\n", errno);
      socks_fail(self);
    }
  else if (!self->super.write.state->length)
    socks_stop_write(self);

  return OOP_CONTINUE;
}

static void
socks_start_write(struct socks_channel *self)
{
  if (!self->super.write.active)
    {
      self->super.write.active = 1;
      global_oop_source->on_fd(global_oop_source, self->super.write.fd, OOP_WRITE,
			       oop_write_socks, self);
    }
}

static void
socks_stop_write(struct socks_channel *self)
{
  if (self->state == SOCKS_CLOSE)
    KILL_RESOURCE(&self->super.super.super);
  
  else if (self->super.write.active)
    {
      self->super.write.active = 0;
      global_oop_source->cancel_fd(global_oop_source, self->super.write.fd, OOP_WRITE);
    }
}
     
static void
socks_method(struct socks_channel *self, uint8_t method)
{
  socks_write(self, ssh_format("%c%c", self->version, method));
}

static void
socks_reply(struct socks_channel *self,
	    uint8_t status,
	    uint8_t atype,
	    uint32_t alength,
	    const uint8_t *addr,
	    uint16_t port)
{
  switch (self->version)
    {
    default:
      fatal("socks_reply: Internal error\n");
      
    case 5:
      socks_write(self, ssh_format("%c%c%c%c%ls%c%c",
				   self->version, status, 0, atype,
				   alength, addr,
				   port >> 8, port & 0xff));
      break;
    case 4:
      assert(atype == SOCKS_IP4);
      assert(alength == 4);

      socks_write(self, ssh_format("%c%c%c%c%ls",
				   0, status ? 91 : 90,
				   port >> 8, port & 0xff,
				   alength, addr));
      break;
    }
}

static struct address_info *
socks2address_info(uint8_t atype,
		   const uint8_t *addr,
		   uint16_t port)
{
  /* The type is checked earlier */
  struct lsh_string *host;
  
  switch (atype)
    {
    default:
      abort();
      
    case SOCKS_IP4:
      host = ssh_format("%di.%di.%di.%di", addr[0], addr[1], addr[2], addr[3]);
      break;
    case SOCKS_IP6:
      /* It's possible to support ipv6 targets without any native ipv6
	 support, but it's easier if we have standard functinos and
	 constants like AF_INET6 and inet_ntop. */
#if WITH_IPV6
      host = lsh_string_ntop(AF_INET6, INET6_ADDRSTRLEN, addr);
      break;
#else
      return NULL;
#endif
    case SOCKS_DNS:
      host = ssh_format("%ls", addr[0], addr + 1);
      break;
    }
  return make_address_info(host, port);
}

static int
socks_command(struct socks_channel *self, uint8_t command,
	      uint8_t addr_type, const uint8_t *addr,
	      uint16_t port)
{
  if (command != SOCKS_CONNECT)
    {
      socks_reply(self, SOCKS_ERROR_COMMAND, SOCKS_NOADDR, 0);
      return 0;
    }
  else
    {
      struct address_info *target = socks2address_info(addr_type, addr, port);
      
      if (!target)
	{
	  socks_reply(self, SOCKS_ERROR_ADDRESS, SOCKS_NOADDR, 0); 
	  return 0;
	}

      if (!channel_open_new_type(self->super.super.connection,
				 &self->super.super,
				 ATOM_LD(ATOM_DIRECT_TCPIP),
				 "%S%i%S%i",
				 target->ip, target->port,
				 self->peer->ip, self->peer->port))
	{
	  socks_reply(self, SOCKS_ERROR_GENERAL, SOCKS_NOADDR, 0);
	  
	  return 0;
	}
      else
	return 1;	
    }
}

static void *
oop_read_socks(oop_source *source UNUSED,
	       int fd, oop_event event, void *state)
{
  CAST(socks_channel, self, state);
  const uint8_t *p;
  uint32_t to_read;
  int res;
  
  assert(event == OOP_READ);
  assert(fd == self->super.read.fd);

  /* The socks client must send a single command and wait for reply.
     So we can safely read all available data, and treat buffer full
     as an error. After processing a command, we can also discard any
     left over data, as there shouldn't be any. */

  to_read = lsh_string_length(self->super.read.buffer) - self->pos;
  if (!to_read)
    {
      werror("socks server: Read buffer full.\n");
      socks_fail(self);
      return OOP_CONTINUE;
    }

  res = lsh_string_read(self->super.read.buffer, self->pos,
			self->super.read.fd, to_read);

  if (res < 0)
    {
      werror("socks server: read error: %e.\n", errno);
      socks_fail(self);
      return OOP_CONTINUE;
    }
  else if (res == 0)
    {
      werror("socks server: unexpected end of file.\n");
      socks_fail(self);
      return OOP_CONTINUE;
    }

  self->pos += res;
  assert(self->pos > 0);

  debug("oop_read_socks: res = %i, pos = %i, length = %i\n", res, self->pos, self->length);
  while (self->super.super.super.alive && self->super.read.active
	 && self->pos >= self->length)
    {
      p = lsh_string_data(self->super.read.buffer);
  
      switch (self->state)
	{
	default:
	  abort();

          /* For socks 4, the command is sent directly,
          
             byte     version ; 4
	     byte     command
	     uint16   port
	     uint32   ip
	     byte[n]  NUL-terminated userid

	     Message length: 9 + length(userid)
          */
          
          /* For socks 5, the initial version exchange is:
          
             byte     version ; 5
	     byte     n; >= 1
	     byte[n]  methods

	     Message length: 2 + n >= 3
          */
      
	case SOCKS_VERSION_HEADER:
	  self->version = p[0];
	  verbose("Socks version %i connection.\n", self->version);

	  switch (self->version)
	    {
	    default:
	      werror("Socks connection of unknown version %i.\n", self->version);
	      socks_fail(self);
	      break;
	  
	    case 4:
	      self->length = SOCKS4_COMMAND_SIZE;
	      self->state = SOCKS4_COMMAND;
	      break;
	  
	    case 5:
	      self->length = 2 + p[1];
	      self->state = SOCKS_VERSION_METHODS;
	      break;
	    }
	  break;

	case SOCKS_VERSION_METHODS:
	  /* We support only method 0 */
	  if (memchr(p+2, SOCKS_NOAUTH, p[1]))
	    {
	      socks_method(self, SOCKS_NOAUTH);
	  
	      self->pos = 0;
	      self->length = SOCKS_COMMAND_SIZE;
	      self->state = SOCKS_COMMAND_HEADER;
	    }
	  else
	    {
	      werror("Socks client doesn't support no authentication!?\n");
	      socks_method(self, SOCKS_NOMETHOD);
	      socks_close(self);
	    }
	  break;

	case SOCKS_COMMAND_HEADER:
	  /* A request has the syntax
	     
	       byte    version
	       byte    command
	       byte    reserved ; 0
	       byte    atype
	       byte[n] address
	       uint16  port     ; network byte order

	       atype : n

	       1 : 4  (ipv4 address, network? byte order)
	       3 : 1 + first byte of address
	       4 : 16 (ipv6 address)

	       We count the first byte of address as part of the header.
	  */
	  if (p[0] != self->version || p[2] != 0)
	    {
	      werror("Invalid socks request.\n");
	      socks_fail(self);
	    }
	  else
	    {
	      self->state = SOCKS_COMMAND_ADDR;
	  
	      switch (p[3])
		{
		case SOCKS_IP4:
		  self->length = 10;
		  break;
		case SOCKS_IP6:
		  self->length = 22;
		  break;
		case SOCKS_DNS:
		  if (p[4] == 0)
		    socks_fail(self);
		  else
		    self->length = 7 +  p[4];
		}
	    }
	  break;

	case SOCKS_COMMAND_ADDR:
	  if (socks_command(self, p[1], p[3], p+4,
			    READ_UINT16(p + self->length - 2)))
	    {
	      self->state = SOCKS_COMMAND_WAIT;
	      socks_stop_read(self);
	    }
	  else
	    {
	      socks_fail(self);
	    }
      
	  break;
      
	case SOCKS4_COMMAND:
	  if (p[SOCKS4_COMMAND_SIZE - 1] != 0)
	    /* FIXME: We should read and ignore the user name. If we
	       are lucky, it's already in the i/o buffer and will be
	       discarded. */
	    werror("Socks 4 usernames not yet supported. May or may not work.\n");

	  if (socks_command(self, p[1], SOCKS_IP4, p+4,
			    READ_UINT16(p + 2)))
	    {
	      self->state = SOCKS_COMMAND_WAIT;
	      socks_stop_read(self);
	    }
	  else
	    {
	      socks_fail(self);
	    }
      
	  break;
	}
    }
  
  return OOP_CONTINUE;
}

static void
socks_start_read(struct socks_channel *self)
{
  if (!self->super.read.active)
    {
      self->super.read.active = 1;
      global_oop_source->on_fd(global_oop_source, self->super.read.fd, OOP_READ,
			       oop_read_socks, self);
    }
}

static void
socks_stop_read(struct socks_channel *self)
{
  if (self->super.read.active)
    {
      self->super.read.active = 0;
      global_oop_source->cancel_fd(global_oop_source, self->super.read.fd, OOP_READ);
    }
}

static void
do_socks_channel_event(struct ssh_channel *s, enum channel_event event)
{
  CAST_SUBTYPE(socks_channel, self, s);

  switch(event)
    {
    case CHANNEL_EVENT_CONFIRM:
      {
	uint32_t left;
	
	/* We don't have the address at the server's end, so we can't
	   pass it along. */
	socks_reply(self, SOCKS_ERROR_NONE, SOCKS_NOADDR, 0);
	socks_stop_write(self);

	left = SOCKS_MAX_SIZE - self->super.write.state->length;
	if (left > 0)
	  /* We used an unnecessarily small initial window. Fix it now. */
	  channel_adjust_rec_window(&self->super.super, left);

	channel_forward_start_io(&self->super);
	break;
      }
    case CHANNEL_EVENT_DENY:
      verbose("Socks forwarding denied by server\n");
      socks_reply(self, SOCKS_ERROR_CONNECTION_REFUSED,
		  SOCKS_NOADDR, 0);

      /* NOTE: When we return, the channel will be killed by
	 channel_finished, and any buffered data will be discarded. We
	 don't try to ensure that the final reply is delivered
	 properly. */
      
      break;      
    case CHANNEL_EVENT_EOF:
      if (!self->super.write.state->length)
	channel_forward_shutdown(&self->super);
      break;

    case CHANNEL_EVENT_SUCCESS:
    case CHANNEL_EVENT_FAILURE:
      break;

    case CHANNEL_EVENT_STOP:
      channel_io_stop_read(&self->super.read);
      break;
    case CHANNEL_EVENT_START:
      channel_forward_start_read(&self->super);
      break;
    case CHANNEL_EVENT_CLOSE:
      /* Do nothing */
      break;
    }
}

static struct socks_channel *
make_socks_channel(struct ssh_connection *connection,
		   int fd, struct address_info *peer)
{
  NEW(socks_channel, self);

  io_register_fd(fd, "socks forwarding");

  init_channel_forward(&self->super, fd, TCPIP_WINDOW_SIZE,
		       do_socks_channel_event);
  self->super.super.connection = connection;

  /* Worst-case margin, for any buffered reply when we take the channel
     into use. */
  self->super.super.rec_window_size -= SOCKS_MAX_SIZE;
  
  self->pos = 0;
  self->length = 3;

  self->peer = peer;
  self->state = SOCKS_VERSION_HEADER;
  self->length = SOCKS_HEADER_SIZE;
  
  self->version = 0;
  self->target = NULL;

  return self;
}

/* The read buffer is replaced when we go into connected mode, but the
   writebuffer is not */
#define SOCKS_READ_BUF_SIZE 100
#define SOCKS_WRITE_BUF_SIZE (SSH_MAX_PACKET * 10)

/* GABA:
   (class
     (name socks_listen_port)
     (super io_listen_port)
     (vars
       (connection object ssh_connection)))
*/

static void
do_socks_accept(struct io_listen_port *s,
		int fd,
		socklen_t addr_length,
		const struct sockaddr *addr)
{
  CAST(socks_listen_port, self, s);

  struct socks_channel *channel
    = make_socks_channel(self->connection, fd, 
			 sockaddr2info(addr_length, addr));
  
  remember_resource(self->connection->resources, &channel->super.super.super);

  socks_start_read(channel);
}

static struct io_listen_port *
make_socks_listen_port(struct ssh_connection *connection,
		       const struct address_info *local)
{
  struct sockaddr *addr;
  socklen_t addr_length;
  int fd;

  addr = io_make_sockaddr(&addr_length,
			  lsh_get_cstring(local->ip), local->port);
  if (!addr)
    return NULL;

  fd = io_bind_sockaddr((struct sockaddr *) addr, addr_length);
  if (fd < 0)
    return NULL;

  {
    NEW(socks_listen_port, self);
    init_io_listen_port(&self->super, fd, do_socks_accept);

    self->connection = connection;
    return &self->super;
  }
}

/* GABA:
   (class
     (name make_socks_server_action)
     (super client_connection_action)
     (vars
       (local const object address_info)))
*/

static void
do_make_socks_server(struct client_connection_action *s,
		     struct ssh_connection *connection)
{
  CAST(make_socks_server_action, self, s);
  struct io_listen_port *port;

  port = make_socks_listen_port(connection, self->local);
  if (!port)
    {
      werror("Invalid local port %S:%i.\n",
	     self->local->ip, self->local->port);
    }
  else if (!io_listen(port))
    {
      werror("Listening on local port %S:%i failed: %e.\n",
	     self->local->ip, self->local->port, errno);
      KILL_RESOURCE(&port->super.super);
    }
  else
    {
      remember_resource(connection->resources, &port->super.super);
    }
}
  
struct client_connection_action *
make_socks_server(const struct address_info *local)
{
  NEW(make_socks_server_action, self);
  self->super.action = do_make_socks_server;
  self->local = local;

  return &self->super;
}
