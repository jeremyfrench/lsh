/* socks.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2004 Niels Möller
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

#include <string.h>

#include "nettle/macros.h"
#include "channel_forward.h"
#include "command.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "tcpforward_commands.h"
#include "werror.h"
#include "xalloc.h"

/* Various protocol constants */
enum {
  /* Version exchange */
  SOCKS_VERSION = 5,
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

/* Message sizes. Maximum size is a request with a 256 byte DNS
   address, 262 bytes in all */
enum {
  SOCKS_HEADER_SIZE = 2,
  SOCKS_COMMAND_SIZE = 5,
  SOCKS_MAX_SIZE = 262,
};

enum socks_state {
  SOCKS_VERSION_HEADER, SOCKS_VERSION_METHODS,
  SOCKS_COMMAND_HEADER, SOCKS_COMMAND_ADDR
};

#include "socks.c.x"

/* GABA:
   (class
     (name socks_connection)
     (super resource)
     (vars
       (connection object ssh_connection)
       (fd object lsh_fd)
       (resources object resource_list)))
*/

static void
do_kill_socks_connection(struct resource *s)
{
  CAST(socks_connection, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;
      KILL_RESOURCE_LIST(self->resources);
    }
}

static void
socks_close(struct socks_connection *self)
{
  close_fd_nicely(self->fd);
  KILL_RESOURCE_LIST(self->resources);
}

static void
socks_fail(struct socks_connection *self)
{
  close_fd(self->fd);
  KILL_RESOURCE_LIST(self->resources);  
}

static void
socks_write(struct socks_connection *self, struct lsh_string *data)
{
  A_WRITE(&self->fd->write_buffer->super, data);
}
     
static void
socks_method(struct socks_connection *self, uint8_t method)
{
  socks_write(self, ssh_format("%c%c", SOCKS_VERSION, method));
}

static void
socks_reply(struct socks_connection *self,
	    uint8_t status,
	    uint8_t atype,
	    uint32_t alength,
	    const uint8_t *addr,
	    uint16_t port)
{
  socks_write(self, ssh_format("%c%c%c%c%ls%c%c",
			       SOCKS_VERSION, status, 0, atype,
			       alength, addr,
			       port >> 8, port & 0xff));
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
	 support, but it's easier if we hafve standard functinos and
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

static void
do_exc_socks_io_handler(struct exception_handler *s UNUSED,
			const struct exception *e)
{
  if (e->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, exc, e);
      if (exc->fd)
	close_fd(exc->fd);

      werror("Socks: %z, (errno = %i)\n", e->msg, exc->error);
    }
  else
    werror("Socks: %z\n", e->msg);
}

/* FIXME: A similar callback must be feined somewhere else? */
/* GABA:  
   (class
     (name socks_close_callback)
     (super lsh_callback)
     (vars
       (socks object socks_connection)))
*/

static void
do_socks_close_callback(struct lsh_callback *s)
{
  CAST(socks_close_callback, self, s);
  KILL_RESOURCE(&self->socks->super);
}

static struct lsh_callback *
make_socks_close_callback(struct socks_connection *socks)
{
  NEW(socks_close_callback, self);
  self->super.f = do_socks_close_callback;
  self->socks = socks;

  return &self->super;
}

/* GABA:
   (expr
     (name socks_forward_local)
     (params
       (connection object ssh_connection)
       (target object address_info))
     (expr
       ;; FIXME: Some duplication with tcpforward_commands.c:forward_local_port
       (lambda (peer)
         ;; Remembering is done by open_direct_tcpip
	 ;; and new_tcpip_channel.
	 (start_io
	   (catch_channel_open 
	     (open_direct_tcpip target peer) connection)))))
*/

static void
socks_command(struct socks_connection *self, uint8_t command,
	      uint8_t addr_type, const uint8_t *addr,
	      uint16_t port)
{
  static const uint8_t noaddr[4] = {0,0,0,0};  
  if (command != SOCKS_CONNECT)
    {
      socks_reply(self, SOCKS_ERROR_COMMAND, SOCKS_IP4, sizeof(noaddr), noaddr, 0); 
    }
  else
    {
      /* FIXME: Always binds an ipv4 port */
      struct sockaddr_in sin;
      socklen_t slen;
      struct lsh_fd *fd;
      struct address_info *target = socks2address_info(addr_type, addr, port);
      struct exception_handler *e;
      
      if (!target)
	{
	  socks_reply(self, SOCKS_ERROR_ADDRESS, SOCKS_IP4, sizeof(noaddr), noaddr, 0); 
	  return;
	}

      e = make_exception_handler(do_exc_socks_io_handler, &default_exception_handler,
				 HANDLER_CONTEXT);
      
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ntohl(0x7f000001L);

      fd = io_bind_sockaddr((struct sockaddr *) &sin, sizeof(sin), e);
      if (!fd)
	{
	  socks_reply(self, SOCKS_ERROR_GENERAL, SOCKS_IP4, sizeof(noaddr), noaddr, 0); 
	  return;
	}
      
      /* Find out which port we got */
      slen = sizeof(sin);
      if (getsockname(fd->fd, (struct sockaddr *) &sin, &slen) < 0)
	{
	  close_fd(fd);
	  socks_reply(self, SOCKS_ERROR_GENERAL, SOCKS_IP4, sizeof(noaddr), noaddr, 0); 
	  return;
	}

      remember_resource(self->resources, &fd->super);

      io_listen(fd, make_listen_callback(socks_forward_local(self->connection, target), e));
      
      socks_reply(self, SOCKS_ERROR_NONE, SOCKS_IP4,
		  4, (uint8_t *) &sin.sin_addr.s_addr,
		  ntohs(sin.sin_port));
    }
}

/* GABA:
   (class
     (name read_socks)
     (super read_handler)
     (vars
       (socks object socks_connection)
       (buffer string)
       (pos . uint32_t)
       (state . "enum socks_state")
       (length . uint32_t)))
*/

static uint32_t
do_read_socks(struct read_handler **h,
	      uint32_t available,
	      const uint8_t *data)
{
  CAST(read_socks, self, *h);
  const uint8_t *p;
  
  if (!available)
    {
      socks_close(self->socks);
      
      *h = NULL;
      return 0;
    }

  if (self->length - self->pos > available)
    {
      lsh_string_write(self->buffer, self->pos, available, data);
      self->pos += available;
      return available;
    }

  available = self->length - self->pos;
  lsh_string_write(self->buffer, self->pos, available, data);

  p = lsh_string_data(self->buffer);
  
  switch (self->state)
    {
      /* Version exchange is:

         byte     version ; 4 or 5
	 byte     n; >= 1
	 byte[n]  methods
      */
      
    case SOCKS_VERSION_HEADER:
      if (p[0] != SOCKS_VERSION || p[1] == 0)
	/* Not valid */
	socks_fail(self->socks);
      else
	{
	  self->length = 2 + p[1];
	  self->state = SOCKS_VERSION_METHODS;
	}
      break;

    case SOCKS_VERSION_METHODS:
      /* We support only method 0 */
      if (memcmp(p+2, SOCKS_NOAUTH, p[1]))
	{
	  socks_method(self->socks, SOCKS_NOAUTH);
	  
	  self->pos = 0;
	  self->length = SOCKS_COMMAND_SIZE;
	  self->state = SOCKS_COMMAND_HEADER;
	}
      else
	{
	  socks_method(self->socks, SOCKS_NOMETHOD);
	  socks_close(self->socks);
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
      if (p[0] != SOCKS_VERSION_METHODS || p[2] != 0)
	socks_fail(self->socks);
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
		socks_fail(self->socks);
	      else
		self->length = 7 +  p[4];
	    }
	}
      break;

    case SOCKS_COMMAND_ADDR:
      socks_command(self->socks, p[1], p[3], p+4,
		    READ_UINT16(p + self->length - 2));
      self->pos = 0;
      self->length = SOCKS_COMMAND_SIZE;
      self->state = SOCKS_COMMAND_HEADER;
      break;
    }
  return available;
}
  
static struct read_handler *
make_read_socks(struct socks_connection *socks)
{
  NEW(read_socks, self);

  self->super.handler = do_read_socks;
  self->socks = socks;
  self->buffer = lsh_string_alloc(SOCKS_MAX_SIZE);
  self->pos = 0;
  self->state = SOCKS_VERSION_HEADER;
  self->length = SOCKS_HEADER_SIZE;

  return &self->super;
}

#define SOCKS_BUF_SIZE 100

static struct socks_connection *
make_socks_connection(struct ssh_connection *connection, struct lsh_fd *fd)
{
  NEW(socks_connection, self);
  init_resource(&self->super, do_kill_socks_connection);

  self->connection = connection;
  self->fd = fd;
  self->resources = make_resource_list();
  remember_resource(self->resources, &fd->super);

  io_read_write(fd, make_buffered_read(SOCKS_BUF_SIZE, make_read_socks(self)),
		SOCKS_BUF_SIZE, make_socks_close_callback(self));

  return self;
}
