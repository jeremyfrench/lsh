/* ssh_read.c
 *
 * Fairly general liboop-based packer reader.
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
#include <errno.h>
#include <string.h>

#include "ssh_read.h"

#include "io.h"
#include "lsh_string.h"
#include "xalloc.h"

#define GABA_DEFINE
# include "ssh_read.h.x"
#undef GABA_DEFINE

/* Returns zero on success. OTherwise returns errno, using EPIPE for
   an unexpected EOF. */
static int
ssh_read(struct lsh_string *data, uint32_t start, int fd, uint32_t length,
	 int allow_eof, uint32_t *done)
{
  int res;
  
  assert(length > 0);
  
  do
    res = lsh_string_read(data, start, fd, length);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    return errno;
  
  else if (res == 0)
    {
      if (allow_eof)
	{
	  *done = 0;
	  return 0;
	}
      else return EPIPE;
    }
  else
    {
      *done = res;
      return 0;
    }
}

/* If STATE is NULL, any callback is removed */
static void
ssh_read_set_callback(struct ssh_read_state *self,
		      oop_source *source, int fd, oop_call_fd state)
{
  if (self->state && self->active)
    source->cancel_fd(source, fd, OOP_READ);

  self->state = state;

  if (self->state && self->active)
    source->on_fd(source, fd, OOP_READ, state, self);
}

void
ssh_read_stop(struct ssh_read_state *self, oop_source *source, int fd)
{
  if (self->state && self->active)
    source->cancel_fd(source, fd, OOP_READ);

  self->active = 0;
}

void
ssh_read_start(struct ssh_read_state *self, oop_source *source, int fd)
{
  if (!self->active && self->state)
    source->on_fd(source, fd, OOP_READ, self->state, self);

  self->active = 1;
}


/* NOTE: All the ssh_read_* functions cancel the liboop callback
   before invoking any of it's own callbacks. */

/* Reads the initial line. This reader will read only one text line,
   and expects the first binary packet to start after the first
   newline character. */
/* FIXME: It might make sense to move the line reader to a separate file. */
static void *
oop_ssh_read_line(oop_source *source, int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(ssh_read_state, self, (struct lsh_object *) state);
  int e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
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
      ssh_read_set_callback(self, source, fd, NULL);
      ERROR_CALLBACK(self->error, e);
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
	  self->pos = left_over;

	  ssh_read_set_callback(self, source, fd, NULL);
	  
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
	      e = EOVERFLOW;
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
  CAST_SUBTYPE(ssh_read_state, self, (struct lsh_object *) state);
  int e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
  to_read = self->header_length - self->pos;

  e = ssh_read(self->header, self->pos, fd, to_read,
	       self->pos == 0, &done);
  if (e)
    {
      ssh_read_set_callback(self, source, fd, NULL);
      ERROR_CALLBACK(self->error, e);
      return OOP_CONTINUE;
    }

  if (done == 0)
    {
      assert(self->pos == 0);
      ssh_read_set_callback(self, source, fd, NULL);

      A_WRITE(self->handler, NULL);
      return OOP_CONTINUE;
    }
  
  self->pos += done;
  assert(self->pos <= self->header_length);
  if (self->pos == self->header_length)
    {
      struct lsh_string *packet;
      ssh_read_set_callback(self, source, fd, NULL);
      self->pos = 0;
      
      packet = self->process(self);
      if (packet)
	{
	  assert(!self->data);
	  self->data = packet;

	  ssh_read_set_callback(self, source, fd, oop_ssh_read_packet);
	}
    }
  return OOP_CONTINUE;      
}

static void *
oop_ssh_read_packet(oop_source *source, int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(ssh_read_state, self, (struct lsh_object *) state);
  int e;
  uint32_t to_read;
  uint32_t done;
  
  assert(event == OOP_READ);
  to_read = lsh_string_length(self->data) - self->pos;

  e = ssh_read(self->data, self->pos, fd, to_read, 0, &done);
  if (e)
    {
      ssh_read_set_callback(self, source, fd, NULL);
      ERROR_CALLBACK(self->error, e);
      return OOP_CONTINUE;
    }  

  self->pos += done;
  assert(self->pos <= lsh_string_length(self->data));
  if (self->pos == lsh_string_length(self->data))
    {
      struct lsh_string *packet = self->data;

      self->pos = 0;
      self->data = NULL;
      /* Prepare to read next packet. */      
      ssh_read_set_callback(self, source, fd, oop_ssh_read_header);
	  
      A_WRITE(self->handler, packet);
    }
  return OOP_CONTINUE; 
}


void
init_ssh_read_state(struct ssh_read_state *self,
		    uint32_t max_header, uint32_t header_length,
		    struct lsh_string * (*process)
		      (struct ssh_read_state *state),
		    struct error_callback *error)
{
  self->state = NULL;
  self->active = 0;
  
  self->pos = 0;
  
  self->header = lsh_string_alloc(max_header);
  self->header_length = header_length;
  
  self->data = NULL;
  self->process = process;
  self->handler = NULL;
  self->error = error;
}

struct ssh_read_state *
make_ssh_read_state(uint32_t max_header, uint32_t header_length,
		    struct lsh_string * (*process)
		      (struct ssh_read_state *state),
		    struct error_callback *error)
{
  NEW(ssh_read_state, self);
  init_ssh_read_state(self, max_header, header_length, process, error);

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

  ssh_read_set_callback(self, source, fd, oop_ssh_read_line);
}

/* NOTE: Depends on the previous value of pos */
void
ssh_read_packet(struct ssh_read_state *self,
		oop_source *source, int fd,
		struct abstract_write *handler)
{
  self->handler = handler;

  ssh_read_set_callback(self, source, fd, oop_ssh_read_header);
}
