/* lshd.c
 *
 * Main server program.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Niels Möller
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

#include <unistd.h>

#include <netinet/in.h>

#include <oop.h>

#include "nettle/macros.h"

#include "crypto.h"
#include "exception.h"
#include "io.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

enum read_state { READ_UNDEF, READ_LINE, READ_HEADER, READ_PACKET };
struct ssh_read_state;

#include "lshd.c.x"

void
ssh_read_line(struct ssh_read_state *self, uint32_t max_length,
	      oop_source *source, int fd,
	      struct abstract_write *handler);

void
ssh_read_header(struct ssh_read_state *self,
		oop_source *source, int fd,
		struct abstract_write *handler);

static oop_source *global_oop_source;

/* GABA:
   (class
     (name header_callback)
     (vars
       (process method "struct lsh_string *"
                       "struct ssh_read_state *" "uint32_t *done")))
*/

#define HEADER_CALLBACK(c, s, p) \
((c)->process((c), (s), (p)))

/* GABA:
   (class
     (name ssh_read_state)
     (vars
       ; Needed only for debugging and sanity checks.
       (state . "enum read_state")
       (pos . uint32_t)
       
       ; Fix buffer space of size SSH_MAX_BLOCK_SIZE       
       (header string)
       ; Current header length
       (header_length . uint32_t);
       
       ; The line or packet being read
       (data string)

       ; Called when header is read. It has total responsibility for
       ; setting up the next state.
       (process object header_callback)
       ; Called for each complete line or packet
       (handler object abstract_write)
       (e object exception_handler)))
*/  

static const struct exception *
ssh_read(struct lsh_string *data, uint32_t start, int fd, uint32_t length,
	 int allow_eof, uint32_t *done)
{
  int res;
  
  assert(length > 0);
  
  do
    res = lsh_string_read(data, start, fd, length);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    return make_io_exception(EXC_IO_READ, NULL,
			     errno, NULL);
  else if (res == 0)
    {
      if (allow_eof)
	{
	  *done = 0;
	  return NULL;
	}
      else
	return make_io_exception(EXC_IO_READ, NULL,
				 0, "Unexpected EOF");
    }
  else
    {
      *done = res;
      return NULL;
    }
}

/* NOTE: All the ssh_read_* functions cancel the liboop callback
   before invoking any of it's own callbacks. */

/* Reads the initial line. This reader will read only one text line,
   and expects the first binary packet to start after the first
   newline character. */
static void *
oop_ssh_read_line(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_state, self, (struct lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
  assert(self->state == READ_LINE);
  assert(self->data);

  to_read = lsh_string_length(self->data) - self->pos;

  /* If we read ahead, we don't want to read more than the header of
     the first packet. */
  if (to_read > self->header_length)
    to_read = self->header_length;

  e = ssh_read(self->data, self->pos, fd, to_read, 0, &done);
  if (e)
    {
    error:
      source->cancel_fd(source, fd, OOP_READ);
      EXCEPTION_RAISE(self->e, e);
      return OOP_CONTINUE;
    }
  else
    {
      const uint8_t *s = lsh_string_data(self->data);
      const uint8_t *eol = memchr(s + self->pos, 0xa, done);
      if (eol)
	{
	  struct lsh_string *line = self->data;
	  /* Excludes the newline character */
	  uint32_t length = eol - s;
	  uint32_t left_over = self->pos + done - length - 1;

	  /* Prepare for header reading mode */
	  self->data = 0;
	  if (left_over)
	    lsh_string_write(self->header, 0, left_over, eol + 1);
	  self->state = READ_UNDEF;
	  self->pos = left_over;

	  source->cancel_fd(source, fd, OOP_READ);
	  
	  /* Ignore any carriage return character */
	  if (length > 0 && s[length-1] == 0x0d)
	    length--;

	  lsh_string_trunc(line, length);
	  A_WRITE(self->handler, line);
	}
      else
	{
	  self->pos += done;
	  assert(self->pos <= lsh_string_length(self->data));

	  if (self->pos == lsh_string_length(self->data))
	    {
	      e = make_io_exception(EXC_IO_READ, NULL,
				    0, "Line too long");
	      goto error;
	    }
	}
      return OOP_CONTINUE;
    }
}

static void *
oop_ssh_read_packet(oop_source *source, int fd, oop_event event, void *state);

static void *
oop_ssh_read_header(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_state, self, (struct lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
  assert(self->state == READ_HEADER);
  to_read = self->header_length - self->pos;

  e = ssh_read(self->data, self->pos, fd, to_read,
	       self->pos == 0, &done);
  if (e)
    {
      source->cancel_fd(source, fd, OOP_READ);
      EXCEPTION_RAISE(self->e, e);
      return OOP_CONTINUE;
    }

  if (done == 0)
    {
      assert(self->pos == 0);
      source->cancel_fd(source, fd, OOP_READ);

      A_WRITE(self->handler, NULL);
      return OOP_CONTINUE;
    }
  
  self->pos += done;
  assert(self->pos <= self->header_length);
  if (self->pos == self->header_length)
    {
      struct lsh_string *packet;
      source->cancel_fd(source, fd, OOP_READ);
      self->pos = 0;
      
      packet = HEADER_CALLBACK(self->process, self, &self->pos);
      if (packet)
	{
	  assert(!self->data);
	  self->state = READ_PACKET;
	  source->on_fd(source, fd, OOP_READ, oop_ssh_read_packet, self);
	}
    }
  return OOP_CONTINUE;      
}

static void *
oop_ssh_read_packet(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_state, self, (struct lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
  assert(self->state == READ_PACKET);
  to_read = lsh_string_length(self->data) - self->pos;

  e = ssh_read(self->data, self->pos, fd, to_read, 0, &done);
  if (e)
    {
      source->cancel_fd(source, fd, OOP_READ);
      EXCEPTION_RAISE(self->e, e);
      return OOP_CONTINUE;
    }  

  self->pos += done;
  assert(self->pos < lsh_string_length(self->data));
  if (self->pos == self->header_length)
    {
      struct lsh_string *packet = self->data;

      self->pos = 0;
      self->data = NULL;
      self->state = READ_UNDEF;
      source->cancel_fd(source, fd, OOP_READ);
	  
      A_WRITE(self->handler, packet);
    }
  return OOP_CONTINUE; 
}

static struct ssh_read_state *
make_ssh_read_state(uint32_t max_header, uint32_t header_length,
		    struct header_callback *process,
		    struct exception_handler *e)
{
  NEW(ssh_read_state, self);
  self->state = READ_UNDEF;
  self->pos = 0;
  
  self->header = lsh_string_alloc(max_header);
  self->header_length = header_length;
  
  self->data = NULL;
  self->process = process;
  self->handler = NULL;
  self->e = e;

  return self;
}

void
ssh_read_line(struct ssh_read_state *self, uint32_t max_length,
	      oop_source *source, int fd,
	      struct abstract_write *handler)
{
  assert(!self->data);
  self->data = lsh_string_alloc(max_length);
  self->pos = 0;
  self->handler = handler;
  self->state = READ_LINE;

  source->on_fd(source, fd, OOP_READ, oop_ssh_read_line, self);
}

/* NOTE: Depends on the previous value of pos */
void
ssh_read_header(struct ssh_read_state *self,
		oop_source *source, int fd,
		struct abstract_write *handler)
{
  /* assert(header_length <= lsh_string_length(self->header)); */

  self->handler = handler;
  self->state = READ_HEADER;

  source->on_fd(source, fd, OOP_READ, oop_ssh_read_header, self);
}

/* NOTE: Usually invoked by the header_callback. */
static void
ssh_read_packet(struct ssh_read_state *self,
		struct lsh_string *data, uint32_t pos,
		oop_source *source, int fd,
		struct abstract_write *handler)
{
  assert(pos < lsh_string_length(data));
  self->pos = pos;
  self->data = data;

  self->handler = handler;
  self->state = READ_PACKET;
  
  source->on_fd(source, fd, OOP_READ, oop_ssh_read_packet, self);
}


/* GABA:
   (class
     (name ssh_process_header)
     (super header_callback)
     (vars
       (sequence_number . uint32_t);
       (connection object lshd_connection)))
*/

static struct lsh_string *
ssh_process_header(struct header_callback *s, struct ssh_read_state *state,
		   uint32_t *done)
{
  CAST(ssh_process_header, self, s);
  const uint8_t *header;
  uint32_t length;
  uint32_t padding;
  uint32_t block_size;
  uint32_t mac_size;
  struct lsh_string *packet;
  
  block_size = self->connection->rec_crypto
    ? self->connection->rec_crypto->block_size : 8;

  if (self->connection->rec_crypto)
    {
      assert(state->header_length == block_size);
      CRYPT(self->connection->rec_crypto,
	    block_size,
	    state->header, 0,
	    state->header, 0);
    }
  header = lsh_string_data(state->header);
  length = READ_UINT32(header);

  /* NOTE: We don't implement a limit at _exactly_
   * rec_max_packet, as we don't include the length field
   * and MAC in the comparison below. */
  if (length > (self->connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("read_packet: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, self->connection->rec_max_packet);
		  
      PROTOCOL_ERROR(self->connection->e, "Packet too large");
      return NULL;
    }

  if ( (length < 12)
       || (length < (block_size - 4))
       || ( (length + 4) % block_size))
    {
      werror("read_packet: Bad packet length %i\n",
	     length);
      PROTOCOL_ERROR(self->connection->e, "Invalid packet length");
      return NULL;
    }
  
  if (self->connection->rec_mac)
    {
      uint8_t s[4];
      WRITE_UINT32(s, self->sequence_number);
      MAC_UPDATE(self->connection->rec_mac, 4, s);
      MAC_UPDATE(self->connection->rec_mac,
		 block_size, header);
    }

  padding = header[4];
  
  if ( (padding < 4)
       || (padding >= length) )
    {
      PROTOCOL_ERROR(self->connection->e,
		     "Bogus padding length.");
      return NULL;
    }
  mac_size = self->connection->rec_mac
    ? self->connection->rec_mac->mac_size : 0;
  
  packet = lsh_string_alloc(length + padding + mac_size);
  lsh_string_write(packet, 0, block_size - 5, header + 5);
  lsh_string_set_sequence_number(packet, self->sequence_number++);
  
  if (block_size - 5 == length + padding + mac_size)
    {
#if 1
      abort();
#else
      /* This can happen only if we use encryption with a large block
	 size, and no mac. */
      assert(!self->connection->rec_mac);
      assert(self->connection->rec_crypto);
      lsh_string_trunc(packet, length);
      lshd_handle_ssh_packet(connection, packet);

      return NULL;
#endif
    }

  *done = block_size - 5;
  return packet;
}

static struct header_callback *
make_ssh_process_header(struct lshd_connection *connection)
{
  NEW(ssh_process_header, self);
  self->super.process = ssh_process_header;
  self->sequence_number = 0;
  self->connection = connection;

  return &self->super;
}

/* GABA:
   (class
     (name lshd_connection)
     (super resource)
     (vars
       (e object exception_handler)

       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)
       (reader object ssh_read_state)
       (rec_max_packet . uint32_t)
       (rec_mac object mac_instance)
       (rec_crypto object crypto_instance)
       (rec_compress object compress_instance)

       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       ; (writer object ...)

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)

       ; Communication with service on top of the transport layer.
       ; This is a bidirectional pipe
       (service_fd . int)
       (service_reader object ssh_read_state)
       ; (service_writer ...)
       ))
*/

static void
kill_lshd_connection(struct resource *s)
{
  CAST(lshd_connection, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;

      global_oop_source->cancel_fd(global_oop_source,
				   self->ssh_input, OOP_READ);
      close(self->ssh_input);
      
      global_oop_source->cancel_fd(global_oop_source,
				   self->ssh_output, OOP_WRITE);

      if (self->ssh_output != self->ssh_input)
	close(self->ssh_output);

      if (self->service_fd != -1)
	{
	  global_oop_source->cancel_fd(global_oop_source,
				       self->service_fd, OOP_READ);
	  global_oop_source->cancel_fd(global_oop_source,
				       self->service_fd, OOP_WRITE);
	  close(self->service_fd);
	}
    }
}

static struct lshd_connection *
make_lshd_connection(int input, int output)
{
  NEW(lshd_connection, self);
  init_resource(&self->super, kill_lshd_connection);
  self->ssh_input = input;
  self->ssh_output = output;

  /* FIXME: Exceptions. All it needs to do is to close the connection.
     We probably don't need any exceptions at all, as the right action
     for any errors is to close the corresponding connection. We
     probably don't even need to kill the child process, as it should
     get EOF. */
  self->e = &default_exception_handler;
  self->reader = make_ssh_read_state(SSH_MAX_BLOCK_SIZE, 8,
				     make_ssh_process_header(self),
				     self->e);
  self->rec_max_packet = SSH_MAX_PACKET;
  self->rec_mac = NULL;
  self->rec_crypto = NULL;
  self->rec_compress = NULL;

  self->send_mac = NULL;
  self->send_crypto = NULL;
  self->send_compress = NULL;
  
  self->service_fd = -1;

  return self;
};

/* GABA:
   (class
     (name lshd_read_handler)
     (super abstract_write)
     (vars
       (connection object lshd_connection)))
*/

static void
lshd_handle_packet(struct abstract_write *s, struct lsh_string *packet)
{
  CAST(lshd_read_handler, self, s);
  werror("Received packet%xS\n", packet);
  lsh_string_free(packet);

  ssh_read_header(self->connection->reader,
		  global_oop_source, self->connection->ssh_input,
		  &self->super);
}

#if 0
static struct abstract_write *
make_lshd_handle_packet(struct lshd_connection *connection)
{
  NEW(lshd_read_handler, self);
  self->connection = connection;
  self->super.write = lshd_handle_packet;
  return &self->super;
}
#endif

static void
lshd_handle_line(struct abstract_write *s, struct lsh_string *line)
{
  CAST(lshd_read_handler, self, s);
  werror("Received handshake line %pS\n", line);
  lsh_string_free(line);
  
  self->super.write = lshd_handle_packet;
  
  ssh_read_header(self->connection->reader,
		  global_oop_source, self->connection->ssh_input,
		  &self->super);
}

static struct abstract_write *
make_lshd_handle_line(struct lshd_connection *connection)
{
  NEW(lshd_read_handler, self);
  self->connection = connection;
  self->super.write = lshd_handle_line;
  return &self->super;
}

static void
lshd_handshake(struct lshd_connection *connection)
{
  if (write_raw(connection->ssh_output,
		16, "SSH-2.0-lshd-ng\n"))
    fatal("Writing greeting failed.\n");

  ssh_read_line(connection->reader, 256,
		global_oop_source, connection->ssh_input,
		make_lshd_handle_line(connection));  
}

/* GABA:
   (class
     (name lshd_port)
     (super resource)
     (vars
       (fd . int)
       ; To we need any options?
       ))
*/

static void
kill_port(struct resource *s)
{
  CAST(lshd_port, self, s);

  if (self->super.alive)
    {
      self->super.alive = 0;
      global_oop_source->cancel_fd(global_oop_source, self->fd, OOP_WRITE);
      close(self->fd);
    }
};

static struct lshd_port *
make_lshd_port(int fd)
{
  NEW(lshd_port, self);
  init_resource(&self->super, kill_port);
  self->fd = fd;
  
  return self;
}

static void *
lshd_port_accept(oop_source *source UNUSED,
		 int fd, oop_event event, void *state)
{
  CAST(lshd_port, self, (struct lsh_object *) state);
  struct lshd_connection *connection;
  struct sockaddr_in peer;
  socklen_t peer_length = sizeof(peer);
  int s;
  
  assert(event == OOP_READ);
  assert(self->fd == fd);

  s = accept(self->fd, (struct sockaddr *) &peer, &peer_length);
  if (s < 0)
    {
      werror("accept faild: %e\n", errno);
      return OOP_CONTINUE;
    }

  connection = make_lshd_connection(s, s); 
  gc_global(&connection->super);

  lshd_handshake(connection);

  return OOP_CONTINUE;
}
		 
static struct resource_list *
open_ports(int port_number)
{
  struct resource_list *ports = make_resource_list();
  struct sockaddr_in sin;
  struct lshd_port *port;
  int yes = 1;
  int s;
  
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    fatal("socket failed: %e\n", errno);

  io_set_nonblocking(s);
  io_set_close_on_exec(s);

  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) <0)
    fatal("setsockopt SO_REUSEADDR failed: %e\n", errno);
  
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(port_number);

  if (bind(s, &sin, sizeof(sin)) < 0)
    fatal("bind failed: %e\n", errno);

  if (listen(s, 256) < 0)
    fatal("listen failed: %e\n", errno);

  port = make_lshd_port(s);
  remember_resource(ports, &port->super);

  global_oop_source->on_fd(global_oop_source, s, OOP_READ,
			   lshd_port_accept, port);

  gc_global(&ports->super);
  return ports;
}

static oop_source *global_oop_source;

int
main(int argc UNUSED, char **argv UNUSED)
{
  global_oop_source = io_init();

  open_ports(4711);
  
  io_run();

  return EXIT_SUCCESS;
}
