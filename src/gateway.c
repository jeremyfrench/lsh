/* gateway.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#include "gateway.h"

#include "channel.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "service.h"
#include "ssh.h"
#include "ssh_write.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "gateway.h.x"
#undef GABA_DEFINE

#define GATEWAY_WRITE_BUFFER_SIZE (100 * SSH_MAX_PACKET)

/* A gateway is a mechanism to delegate some channels to a separate
 * process. The main lsh process opens a unix domain socket, and other
 * processes can connect and read and write clear text ssh packets.
 * Packets written to the gateway socket are forwarded to the remote
 * server. And certain packets received from the remote server are
 * delegated and can be read from the gateway.
 *
 * Most packets are passed through, with only the channel numbers
 * translated. CHANNEL_CLOSE messages are an exception, since the
 * close handshake is associated with deallocation of channel
 * numbersw, which are independent for the gateway connection and with
 * the shared connection to the remote ssh server.
 *
 * Currently, all gatewayed channels must be opened by the gateway
 * client; if the client requests tcpip och x11 forwarding, the
 * corresponding CHANNEL_OPEN requests from the server will be
 * refused. */

/* The gateway socket is named "TMP/x-lsh-USER/HOST%REMOTE-USER".
 *
 * The choice of the '%' separator in the socket name makes sure we
 * don't collide with any valid dns names, or with literal IPv4 or IPv6
 * addresses. And it should be really rare in usernames. */

static int
check_string_l(unsigned length, const uint8_t *s)
{
  unsigned i;
  for (i = 0; i<length; i++)
    switch(*s++)
      {
      case  '\0':
      case '%':
      case '/':
	return 0;
      default:
	break;
      }
  return 1;
}

static int
check_string(const uint8_t *s)
{
  for (;;)
    switch(*s++)
      {
      case  '\0':
	return 1;
      case '%':
      case '/':
	return 0;
      default:
	break;
      }
}

struct local_info *
make_gateway_address(const char *local_user, const char *remote_user,
		     const char *target)
{
  char *tmp = getenv(ENV_TMPDIR);
  unsigned length = strlen(target);
  if (!tmp)
    tmp = "/tmp";
  
  if (check_string(local_user)
      && check_string(remote_user)
      && check_string_l(length, target))
    return make_local_info(ssh_format("%lz/x-lsh-%lz", tmp, local_user),
			   ssh_format("%lz:%lz", target, remote_user));
  else
    return NULL;
}

static void
kill_gateway_connection(struct resource *s)
{
  CAST(gateway_connection, self, s);
  if (self->super.super.alive)
    {
      uint32_t i;
      werror("kill_gateway_connection\n");

      self->super.super.alive = 0;      

      /* NOTE: We don't add the gatewayed channels to super.resources,
       * instead, we use channel_close on all active channels when the
       * gateway is killed. That way, the channels are kept alive
       * until the CHANNEL_CLOSE handshake is finished. */
      
      for (i = 0; i < self->super.used_channels; i++)
	if (self->super.alloc_state[i] == CHANNEL_ALLOC_ACTIVE)
	  {
	    assert(self->super.channels[i]);
	    channel_close(self->super.channels[i]);
	  }
      
      KILL_RESOURCE_LIST(self->super.resources);

      io_close_fd(self->fd);
      self->fd = -1;
    }
}

static void
gateway_write_packet(struct gateway_connection *connection,
		     struct lsh_string *packet)
{
  uint32_t done;
  int msg;
  
  assert(lsh_string_length(packet) > 0);
  msg = lsh_string_data(packet)[0];
  trace("gateway_write_packet: Writing packet of type %T (%i)\n", msg, msg);
  debug("packet contents: %xS\n", packet);

  /* Sequence number not supported */
  packet = ssh_format("%i%fS", 0, packet);
  
  done = ssh_write_data(connection->writer,
			connection->fd, 0, 
			STRING_LD(packet));
  lsh_string_free(packet);

  /* FIXME: Check if we're filling up the buffer; if so we must stop
     channels from sending more data. */
  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (connection->writer->length)
	{
	  /* FIXME: Install a write callback. If our write buffer is
	     getting full, generate CHANNEL_EVENT_STOP events on all
	     channels, and stop reading on all gateways. */
	  werror("gateway_write_packet: ssh_write_data couldn't write all data.\n");
	}
    }
  else
    {
      werror("gateway_write_packet: Write failed: %e\n", errno);
      KILL_RESOURCE(&connection->super.super);
    }
}

static void
gateway_disconnect(struct gateway_connection *connection,
		   uint32_t reason, const char *msg)
{
  werror("disconnecting gateway: %z.\n", msg);

  gateway_write_packet(connection,
		       format_disconnect(reason, msg, ""));

  /* FIXME: If the write buffer is full, the disconnect message will
     likely be lost. */
  KILL_RESOURCE(&connection->super.super);
}

static void
gateway_start_read(struct gateway_connection *self);

static void *
oop_read_gateway(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(gateway_connection, self, (struct lsh_object *) state);

  assert(event == OOP_READ);

  for (;;)
    {
      enum ssh_read_status status;

      uint32_t seqno;
      uint32_t length;      
      const uint8_t *packet;
      const char *error_msg;
      uint8_t msg;
      
      status = service_read_packet(self->reader, fd,
				   &error_msg,
				   &seqno, &length, &packet);
      fd = -1;

      switch (status)
	{
	case SSH_READ_IO_ERROR:
	  werror("Read from gateway failed: %e\n", errno);
	  KILL_RESOURCE(&self->super.super);
	  break;
	case SSH_READ_PROTOCOL_ERROR:
	  werror("Invalid data from gateway: %z\n", error_msg);
	  KILL_RESOURCE(&self->super.super);
	  break;
	case SSH_READ_EOF:
	  werror("Gateway disconnected.\n", error_msg);
	  KILL_RESOURCE(&self->super.super);
	  return OOP_CONTINUE;
	  break;
	case SSH_READ_PUSH:
	case SSH_READ_PENDING:
	  return OOP_CONTINUE;

	case SSH_READ_COMPLETE:
	  if (!length)
	    gateway_disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
			       "lsh received an empty packet from a gateway");

	  msg = packet[0];

	  if (msg < SSH_FIRST_CONNECTION_GENERIC)
	    /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
	    gateway_disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
			       "lsh received a transport or userauth layer packet from a gateway");

	  else if (!gateway_packet_handler(self, length, packet))
	    gateway_write_packet(self, format_unimplemented(seqno));	    
	}
    }
}

static void
gateway_start_read(struct gateway_connection *self)
{
  global_oop_source->on_fd(global_oop_source,
			   self->fd, OOP_READ,
			   oop_read_gateway, self);  
}

static void
do_write_packet(struct ssh_connection *s, struct lsh_string *packet)
{
  CAST(gateway_connection, self, s);

  gateway_write_packet(self, packet);
}

static void
do_disconnect(struct ssh_connection *s, uint32_t reason, const char *msg)
{
  CAST(gateway_connection, self, s);
  gateway_disconnect(self, reason, msg);  
}

struct gateway_connection *
make_gateway_connection(struct ssh_connection *shared, int fd)
{
  NEW(gateway_connection, self);
  init_ssh_connection(&self->super, kill_gateway_connection,
		      do_write_packet, do_disconnect);

  self->shared = shared;
  
  io_register_fd(fd, "lsh gateway connection");

  self->fd = fd;
  self->reader = make_service_read_state();
  gateway_start_read(self);

  self->writer = make_ssh_write_state(GATEWAY_WRITE_BUFFER_SIZE);
  
  return self;
}
