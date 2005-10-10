/* socks.c
 *
 * References:
 *
 * Socks4 is described in http://archive.socks.permeo.com/protocol/socks4.protocol.
 * Socks5 is described in RFC 1928.
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "nettle/macros.h"
#include "channel_forward.h"
#include "command.h"
#include "format.h"
#include "io_commands.h"
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

struct command_2 socks_handshake;
#define SOCKS_HANDSHAKE (&socks_handshake.super.super)

#include "socks.c.x"

static const uint8_t ip4_noaddr[4] = {0,0,0,0};

#define SOCKS_NOADDR SOCKS_IP4, sizeof(ip4_noaddr), ip4_noaddr

/* Forward declarations */
static void
socks_start_write(struct socks_connection *self);

static void
socks_stop_write(struct socks_connection *self);

static void
socks_start_read(struct socks_connection *self);

static void
socks_stop_read(struct socks_connection *self);


/* GABA:
   (class
     (name socks_connection)
     (super resource)
     (vars
       (connection object ssh_connection)

       ; We use the channel's read and write buffers
       ; FIXME: It would be cleaner to use our own buffers,
       ; and not allocate the channel until we try opening it.
       (channel object channel_forward)

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
do_kill_socks_connection(struct resource *s)
{  
  CAST(socks_connection, self, s);
  if (self->super.alive)
    {
      trace("do_kill_socks_connection\n");
      
      self->super.alive = 0;
      if (self->channel)
	KILL_RESOURCE(&self->channel->super.super);
    }
}

static struct socks_connection *
make_socks_connection(struct ssh_connection *connection,
		      struct listen_value *lv)
{
  NEW(socks_connection, self);
  init_resource(&self->super, do_kill_socks_connection);

  self->connection = connection;
  
  self->channel = make_channel_forward(lv->fd, TCPIP_WINDOW_SIZE);
  /* Worst-case margin, for any buffered reply when we take the channel
     into use. */
  self->channel->super.rec_window_size -= SOCKS_MAX_SIZE;
  
  self->pos = 0;
  self->length = 3;

  self->peer = lv->peer;
  self->state = SOCKS_VERSION_HEADER;
  self->length = SOCKS_HEADER_SIZE;
  
  self->version = 0;
  self->target = NULL;

  return self;
}

static void
socks_close(struct socks_connection *self)
{
  self->state = SOCKS_CLOSE;
  if (self->channel->write.state->length)
    global_oop_source->cancel_fd(global_oop_source, self->channel->read.fd, OOP_READ);
  else
    KILL_RESOURCE(&self->super);
}

static void
socks_fail(struct socks_connection *self)
{
  KILL_RESOURCE(&self->super);
}

static void
socks_write(struct socks_connection *self, struct lsh_string *data)
{
  uint32_t done = ssh_write_data(self->channel->write.state, self->channel->write.fd,
				 0, STRING_LD(data));

  lsh_string_free(data);

  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (self->channel->write.state->length > 0)
	socks_start_write(self);
      else
	socks_stop_write(self);
    }
  else
    {
      werror("socks server: write failed: %e\n", errno);
      socks_fail(self);      
    }
}

static void *
oop_write_socks(oop_source *source UNUSED,
		int fd, oop_event event, void *state)
{
  CAST(socks_connection, self, state);
  
  assert(event == OOP_WRITE);
  assert(fd == self->channel->write.fd);

  if (!ssh_write_flush(self->channel->write.state, self->channel->write.fd, 0))
    {
      werror("socks server: write failed: %e\n", errno);
      socks_fail(self);
    }
  else if (!self->channel->write.state->length)
    socks_stop_write(self);

  return OOP_CONTINUE;
}

static void
socks_start_write(struct socks_connection *self)
{
  if (!self->channel->write.active)
    {
      self->channel->write.active = 1;
      global_oop_source->on_fd(global_oop_source, self->channel->write.fd, OOP_WRITE,
			       oop_write_socks, self);
    }
}

static void
socks_stop_write(struct socks_connection *self)
{
  if (self->state == SOCKS_CLOSE)
    KILL_RESOURCE(&self->super);
  
  else if (self->channel->write.active)
    {
      self->channel->write.active = 0;
      global_oop_source->cancel_fd(global_oop_source, self->channel->write.fd, OOP_WRITE);
    }
}
     
static void
socks_method(struct socks_connection *self, uint8_t method)
{
  socks_write(self, ssh_format("%c%c", self->version, method));
}

static void
socks_reply(struct socks_connection *self,
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

/* GABA:
   (class
     (name socks_continuation)
     (super command_continuation)
     (vars
       (socks object socks_connection)))
*/

static void
do_socks_continuation(struct command_continuation *s, struct lsh_object *x)
{
  CAST(socks_continuation, self, s);
  CAST_SUBTYPE(channel_forward, channel, x);
  uint32_t left;
  
  assert(channel == self->socks->channel);
  /* We don't have the address at the server's end, so we can't pass it along. */
  socks_reply(self->socks, SOCKS_ERROR_NONE, SOCKS_NOADDR, 0);
  socks_stop_write(self->socks);

  self->socks->channel = NULL;
  self->socks->super.alive = 0;

  left = SOCKS_MAX_SIZE - channel->write.state->length;
  if (left > 0)
    /* We used an unnecessarily small initial window. Fix it now. */
    channel_adjust_rec_window(&channel->super, left);
}

static struct command_continuation *
make_socks_continuation(struct socks_connection *socks)
{
  NEW(socks_continuation, self);
  self->super.c = do_socks_continuation;
  self->socks = socks;

  return &self->super;
}

/* GABA:
   (class
     (name socks_exception_handler)
     (super exception_handler)
     (vars
       (socks object socks_connection)))
*/

static void
do_exc_socks_handler(struct exception_handler *s,
		     const struct exception *e)
{
  CAST(socks_exception_handler, self, s);

  uint8_t reply = SOCKS_ERROR_GENERAL;

  if (e->type == EXC_CHANNEL_OPEN)
    {
      if (e->subtype == SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
	reply = SOCKS_ERROR_NOT_ALLOWED;
      else if (e->subtype == SSH_OPEN_CONNECT_FAILED)
	reply = SOCKS_ERROR_CONNECTION_REFUSED;
    }
  verbose("Socks forwarding denied by server: %z\n", e->msg);
  socks_reply(self->socks, reply, SOCKS_NOADDR, 0);

  /* FIXME: When we return, the channel will be killed by
     channel_finished, and any buffered data will be discarded. We
     don't try to ensure that the final reply is delivered
     properly. */

  socks_stop_write(self->socks);
  self->socks->channel = NULL;
  self->socks->super.alive = 0;
}

static struct exception_handler *
make_socks_exception_handler(struct socks_connection *socks,
			     const char *context)
{
  NEW(socks_exception_handler, self);
  self->super.raise = do_exc_socks_handler;
  self->super.context = context;
  
  self->socks = socks;
  return &self->super;
}

static int
socks_command(struct socks_connection *self, uint8_t command,
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

      if (!channel_open_new_type(self->connection, &self->channel->super,
				 ATOM_DIRECT_TCPIP,
				 "%S%i%S%i",
				 target->ip, target->port,
				 self->peer->ip, self->peer->port))
	{
	  socks_reply(self, SOCKS_ERROR_GENERAL, SOCKS_NOADDR, 0);
	  
	  return 0;
	}
      else
	{
	  assert(!self->channel->super.channel_open_context);
	  self->channel->super.channel_open_context
	    = make_command_context(make_socks_continuation(self),
				   make_socks_exception_handler(self, HANDLER_CONTEXT));

	  return 1;
	}
    }
}

static void *
oop_read_socks(oop_source *source UNUSED,
	       int fd, oop_event event, void *state)
{
  CAST(socks_connection, self, state);
  const uint8_t *p;
  uint32_t to_read;
  int res;
  
  assert(event == OOP_READ);
  assert(fd == self->channel->read.fd);

  /* The socks client must send a single command and wait for reply.
     So we can safely read all available data, and treat buffer full
     as an error. After processing a command, we can also discard any
     left over data, as there shouldn't be any. */

  to_read = lsh_string_length(self->channel->read.buffer) - self->pos;
  if (!to_read)
    {
      werror("socks server: Read buffer full.\n");
      socks_fail(self);
      return OOP_CONTINUE;
    }

  res = lsh_string_read(self->channel->read.buffer, self->pos,
			self->channel->read.fd, to_read);

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
  while (self->super.alive && self->channel->read.active
	 && self->pos >= self->length)
    {
      p = lsh_string_data(self->channel->read.buffer);
  
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
socks_start_read(struct socks_connection *self)
{
  if (!self->channel->read.active)
    {
      self->channel->read.active = 1;
      global_oop_source->on_fd(global_oop_source, self->channel->read.fd, OOP_READ,
			       oop_read_socks, self);
    }
}

static void
socks_stop_read(struct socks_connection *self)
{
  if (self->channel->read.active)
    {
      self->channel->read.active = 0;
      global_oop_source->cancel_fd(global_oop_source, self->channel->read.fd, OOP_READ);
    }
}

/* The read buffer is replaced when we go into connected mode, but the
   writebuffer is not */
#define SOCKS_READ_BUF_SIZE 100
#define SOCKS_WRITE_BUF_SIZE (SSH_MAX_PACKET * 10)

/* (socks_handshake connection peer) */
DEFINE_COMMAND2(socks_handshake)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(ssh_connection, connection, a1);
  CAST(listen_value, lv, a2);
  
  struct socks_connection *self = make_socks_connection(connection, lv);
  io_register_fd(lv->fd, "socks forwarding");
  remember_resource(connection->resources, &self->super);

  socks_start_read(self);

  COMMAND_RETURN(c, self);
}

/* GABA:
   (expr
     (name make_socks_server)
     (params
       (local object address_info))
     (expr
       (lambda (connection)
         (connection_remember connection
           (listen_tcp
	     (lambda (peer)
	       (socks_handshake connection peer))
	     ; NOTE: The use of prog1 is needed to delay the bind call
	     ; until the (otherwise ignored) connection argument is
	     ; available.
	     (prog1 local connection))))))
*/
