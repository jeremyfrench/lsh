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

#include <oop.h>

#include "lsh_string.h"
#include "ssh.h"

enum read_state { READ_UNDEF, READ_LINE, READ_HEADER, READ_PACKET };
struct ssh_read_state;

/* GABA:
   (class
     (name header_callback)
     (vars
       (process method int "struct ssh_read_state *")))
*/

#define HEADER_CALLBACK(c, s) \
((c)->process((c), (r)))

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
  assert(to_read > 0);
  
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
      done = res;
      return NULL;
    }
}

/* NOTE: All the ssh_read_* functions cancel the liboop callback
   before invoking any of it's own callbacks. */

/* Reads the initial line. This reader will read only one text line,
   and expects the first binary packet to start after the first
   newline character. */
static void *
ssh_read_line(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_line, self, (lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
  assert(self->state == READ_LINE);
  if (!self->data)
    self->data = lsh_string_alloc(self->length);

  to_read = lsh_string_length(self->data) - self->pos;

  /* If we read ahead, we don't want to read more than the header of
     the first packet. */
  if (to_read > header_length)
    to_read = header_length;

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
	  uint32_t left_over = self->pos + res - length - 1;

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
	  self->pos += res;
	  assert(line->pos <= lsh_string_length(self->data));

	  if (line->pos == lsh_string_length(self->data))
	    {
	      e = make_io_exception(EXC_IO_READ, NULL,
				    0, "Line too long");
	      goto error;
	    }
	  return OOP_CONTINUE;
	}
    }
}

static void *
ssh_read_header(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_line, self, (lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
  assert(self->state == READ_HEADER);
  to_read = self->header_length - self->pos;

  e = ssh_read_line(self->header_length, self->pos, fd, to_read,
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
  assert(pos <= self->header_length);
  if (pos == self->header_length)
    {
      source->cancel_fd(source, fd, OOP_READ);
      pos = 0;
      HEADER_CALLBACK(self->process, self);
    }
  return OOP_CONTINUE;      
}

static void *
ssh_read_packet(oop_source *source, int fd, oop_event event, void *state)
{
  CAST(ssh_read_line, self, (lsh_object *) state);
  const struct exception *e;
  uint32_t to_read;
  uint32_t done;
  
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
  assert(pos < lsh_string_length(self->data));
  if (pos == self->header_length)
    {
      lsh_string *packet = self->data;

      self->pos = 0;
      self->data = NULL;
      self->state = READ_UNDEF;
      source->cancel_fd(source, fd, OOP_READ);
	  
      A_WRITE(self->handler, data);
    }
  return OOP_CONTINUE; 
}

struct ssh_read_state *
make ssh_read_state(uint32_t max_header, uint32_t header_length,
		    struct exception_handler *e)
{
  NEW(self, ssh_read_state);
  self->state = READ_UNDEF;
  self->pos = 0;
  
  self->header = lsh_string_alloc(max_header);
  self->header_length = header_length;
  
  self->data = NULL;
  self->process = NULL;
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

  source->on_fd(source, fd, OOP_READ, ssh_read_line);
}

/* NOTE: Depends on the previous value of pos */
void
ssh_read_header(struct ssh_read_state *self,
		oop_source *source, int fd,
		struct header_callback *process)
{
  assert(header_length <= lsh_string_length(self->header));

  self->process = process;
  self->state = READ_HEADER;

  source->on_fd(source, fd, OOP_READ, ssh_read_header);
}

/* NOTE: Usually invoked by the header_callback. */
void
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
  
  source->on_fd(source, fd, OOP_READ, ssh_read_packet);
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

/* GABA:
   (class
     (name ssh_process_header)
     (super header_callback)
     (vars
       (sequence_number . uint32_t);
       (connection lshd_connection)))
*/

void
ssh_process_header(struct header_callback *s, struct ssh_read_state *state)
{
  CAST(ssh_process_header, self, s);
  const uint8_t *header;
  uint32_t length;
  uint32_t padding;
  uint32_t block_size;
  uint32_t mac_size;
  const uint8_t *block;
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
  length = READ_UINT32(block);

  /* NOTE: We don't implement a limit at _exactly_
   * rec_max_packet, as we don't include the length field
   * and MAC in the comparison below. */
  if (length > (closure->connection->rec_max_packet + SSH_MAX_PACKET_FUZZ))
    {
      werror("read_packet: Receiving too large packet.\n"
	     "  %i octets, limit is %i\n",
	     length, self->connection->rec_max_packet);
		  
      PROTOCOL_ERROR(self->connection->e, "Packet too large");
      return;
    }

  if ( (length < 12)
       || (length < (block_size - 4))
       || ( (length + 4) % block_size))
    {
      werror("read_packet: Bad packet length %i\n",
	     length);
      PROTOCOL_ERROR(self->connection->e, "Invalid packet length");
      return;
    }

  block = lsh_string_data(state->header);
  
  if (self->connection->rec_mac)
    {
      uint8_t s[4];
      WRITE_UINT32(s, self->sequence_number);
      MAC_UPDATE(self->connection->rec_mac, 4, s);
      MAC_UPDATE(self->connection->rec_mac,
		 block_size, block);
    }

  padding = block[4];
  
  if ( (padding < 4)
       || (padding >= length) )
    {
      PROTOCOL_ERROR(closure->connection->e,
		     "Bogus padding length.");
      return;
    }
  mac_size = self->connection->rec_mac
    ? self->connection->rec_mac->mac_size : 0;
  
  packet = lsh_string_alloc(length + padding + mac_size);
  lsh_string_write(packet, 0, block_size - 5, block + 5);
  lsh_string_set_sequence_number(packet, self->sequence_number++);
  
  if (block_size - 5 == length + padding + mac_size)
    {
      /* This can happen only if we use encryption with a large block
	 size, and no mac. */
      assert(!self->connection->rec_mac);
      assert(self->connection->rec_crypto);
      lsh_string_trunc(packet, length);
      lshd_handle_ssh_packet(connection, packet);

      return NULL;
    }
  ssh_read_packet(state, packet, block_size - 5,
		  source, self->connection->ssh_input,
		  connection->packet_handler);
}

  
/* GABA:
   (class
     (name lshd_port)
     (vars
       (next object lshd_port)
       (fd . int)
       ; To we need any options?
       ))
*/
