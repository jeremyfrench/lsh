/* transport_forward.c
 *
 * Uses the transport protocol and forwards unecrypted packets to and
 * from other fd:s.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#include <unistd.h>

#include "nettle/macros.h"

#include "format.h"
#include "io.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "transport_forward.h"

#define GABA_DEFINE
# include "transport_forward.h.x"
#undef GABA_DEFINE

#define FORWARD_WRITE_BUFFER_SIZE (3 * SSH_MAX_PACKET)

static void
forward_start_read(struct transport_forward *self);

static void
forward_stop_read(struct transport_forward *self);

static void
forward_start_write(struct transport_forward *self);

static void
forward_stop_write(struct transport_forward *self);

void
init_transport_forward(struct transport_forward *self,
		       void (*kill)(struct resource *s),
		       struct transport_context *ctx,
		       int ssh_input, int ssh_output,
		       int (*event)(struct transport_connection *,
				    enum transport_event event))
{
  init_transport_connection(&self->super, kill, ctx, ssh_input, ssh_output, event);

  self->service_in = self->service_out = -1;

  self->service_reader = NULL;
  self->service_writer = NULL;
}

struct transport_forward *
make_transport_forward(void (*kill)(struct resource *s),
		       struct transport_context *ctx,
		       int ssh_input, int ssh_output,
		       int (*event)(struct transport_connection *,
				    enum transport_event event))
{
  NEW(transport_forward, self);
  init_transport_forward(self, kill, ctx, ssh_input, ssh_output, event);
  return self;
}

static void
transport_forward_close(struct transport_forward *self)
{
  if (self->service_in >= 0)
    {
      io_close_fd(self->service_in);

      if (self->service_in != self->service_out)
	io_close_fd(self->service_out);

      self->service_in = self->service_out = -1;
    }
}

/* Intended to be called by the kill method in child class. */
void
transport_forward_kill(struct transport_forward *self)
{
  transport_forward_close(self);
  transport_connection_kill(&self->super);
}

/* Communication with service layer */

static void *
oop_read_service(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(transport_forward, self, (struct lsh_object *) state);

  assert(fd == self->service_in);
  assert(event == OOP_READ);

  /* FIXME: Must check self->service_read_active, and stop the reading
     loop in case the write buffer fills up and the transport
     generates a TRANSPORT_EVENT_STOP_APPLICATION. */
  while (self->service_in >= 0 && self->service_read_active)
    {
      enum service_read_status status;
      uint32_t seqno;
      uint32_t length;
      const uint8_t *packet;
      const char *msg;

      status = service_read_packet(self->service_reader, fd, &msg,
				   &seqno, &length, &packet);
      fd = -1;

      switch (status)
	{
	case SERVICE_READ_IO_ERROR:
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Read from service layer failed.");
	  break;
	case SERVICE_READ_PROTOCOL_ERROR:
	  werror("Invalid data from service layer: %z\n", msg);
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Invalid data from service layer.");
	  break;
	case SERVICE_READ_EOF:
	  transport_disconnect(&self->super,
			       SSH_DISCONNECT_BY_APPLICATION,
			       "Service done.");
	  break;
	case TRANSPORT_READ_PUSH:
	  transport_send_packet(&self->super, 0, NULL);
	  /* Fall through */
	case TRANSPORT_READ_PENDING:
	  return OOP_CONTINUE;

	case SERVICE_READ_COMPLETE:
	  if (!length)
	    transport_disconnect(&self->super, SSH_DISCONNECT_BY_APPLICATION,
				 "Received empty packet from service layer.");
	  else
	    {
	      /* FIXME: This is unnecessary allocation and copying. */
	      transport_send_packet(&self->super, 0,
				    ssh_format("%ls", length, packet));
	      if (packet[0] == SSH_MSG_DISCONNECT)
		transport_close(&self->super, 1);
	    }
	}
    }
  return OOP_CONTINUE;
}

static void
forward_start_read(struct transport_forward *self)
{
  if (!self->service_read_active)
    {
      self->service_read_active = 1;
      global_oop_source->on_fd(global_oop_source, self->service_in,
			       OOP_READ, oop_read_service, self);
    }
}

static void
forward_stop_read(struct transport_forward *self)
{
  if (self->service_read_active)
    {
      self->service_read_active = 0;
      global_oop_source->cancel_fd(global_oop_source,
				   self->service_in, OOP_READ);
    }
}

static void *
oop_write_service(oop_source *source UNUSED,
		  int fd, oop_event event, void *state)
{  
  CAST_SUBTYPE(transport_forward, self, (struct lsh_object *) state);
  uint32_t done;
  
  assert(fd == self->service_out);
  assert(event == OOP_WRITE);

  done = ssh_write_flush(self->service_writer, self->service_out, 0);
  if (done > 0)
    {
      if (!self->service_writer->length)
	forward_stop_write(self);

      if (ssh_write_available(self->service_writer) > SSH_MAX_PACKET + 8)
	transport_start_read(&self->super);
    }
  else if (errno != EWOULDBLOCK)
    {
      if (errno == EOVERFLOW)
	werror("Buffer full from ssh_write_flush! Should not happen.\n");
	
      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Connection to service layer failed.");
    }

  return OOP_CONTINUE;
}

static void
forward_start_write(struct transport_forward *self)
{
  if (!self->service_write_active)
    {
      self->service_write_active = 1;
      global_oop_source->on_fd(global_oop_source, self->service_out,
			       OOP_WRITE, oop_write_service, self);
    }
}

static void
forward_stop_write(struct transport_forward *self)
{
  if (self->service_write_active)
    {
      self->service_write_active = 0;
      global_oop_source->cancel_fd(global_oop_source,
				   self->service_out, OOP_WRITE);
    }
}

static int
forward_event_handler(struct transport_connection *connection,
		      enum transport_event event)
{
  CAST_SUBTYPE(transport_forward, self, connection);
  switch (event)
    {
    case TRANSPORT_EVENT_START_APPLICATION:
      /* FIXME: Must also arrange so that buffered data is read. */
      forward_start_read(self);
      break;

    case TRANSPORT_EVENT_STOP_APPLICATION:
      forward_stop_read(self);
      break;

    case TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE:
      fatal("Internal error\n");

    case TRANSPORT_EVENT_CLOSE:
      assert(self->service_in >= 0);
      
      /* FIXME: Should maybe allow service buffer to drain. On the
	 other hand, the connection layer exchange of EOF and CLOSE
	 messages should be sufficient to ensure that all important
	 data is delivered. */
      transport_forward_close(self);
      break;

    case TRANSPORT_EVENT_PUSH:
      if (self->service_out >= 0 && self->service_writer->length > 0)
	{
	  uint32_t done = ssh_write_flush(self->service_writer, self->service_out, 0);

	  if (done > 0 || errno == EWOULDBLOCK)
	    {
	      if (self->service_writer->length)
		forward_start_write(self);
	      else
		forward_stop_write(self);
	    }
	  else
	    {
	      if (errno == EOVERFLOW)
		werror("Buffer full from ssh_write_flush! Should not happen.\n");
	
	      transport_disconnect(&self->super,
				   SSH_DISCONNECT_BY_APPLICATION,
				   "Connection to service layer failed.");
	    }
	}
    }
  return 0;
}

/* Handles decrypted packets above the ssh transport layer. */
static int
forward_packet_handler(struct transport_connection *connection,
		       uint32_t seqno, uint32_t length, const uint8_t *packet)
{
  CAST_SUBTYPE(transport_forward, self, connection);
  uint8_t header[8];
  uint32_t done;
  
  assert(length > 0);
  
  if (ssh_write_available(self->service_writer) < length + sizeof(header))
    return 0;

  WRITE_UINT32(header, seqno);
  WRITE_UINT32(header + 4, length);

  /* FIXME: Avoid pushing out the header */
  done = ssh_write_data(self->service_writer,
			self->service_out, 0,
			sizeof(header), header);
  if (done > 0 || errno == EWOULDBLOCK)
    done = ssh_write_data(self->service_writer,
			  self->service_out, 0,
			  length, packet);

  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (self->service_writer->length)
	forward_start_write(self);
      else
	forward_stop_write(self);
    }
  else
    {
      if (errno == EOVERFLOW)
	werror("Buffer full from ssh_write_flush! Should not happen.\n");

      transport_disconnect(&self->super,
			   SSH_DISCONNECT_BY_APPLICATION,
			   "Connection to service layer failed.");
    }
  return 1;
}

void
transport_forward_setup(struct transport_forward *self,
			int service_in, int service_out)
{
  assert (self->service_in == -1);

  self->service_in = service_in;
  self->service_reader = make_service_read_state();

  self->service_out = service_out;
  self->service_writer = make_ssh_write_state(FORWARD_WRITE_BUFFER_SIZE);
  
  self->super.event_handler = forward_event_handler;
  self->super.packet_handler = forward_packet_handler;

  io_register_fd(service_in, "transport service read pipe");
  if (service_out != service_in)
    io_register_fd(service_out, "transport service write pipe");
    
  forward_start_read(self);
}
