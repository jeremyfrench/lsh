/* oop-line-file.c */

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

#include "oop-line.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>

int _oop_line_done;

#define MAGIC 0x74d2

struct oop_line_file
{
  oop_line oop;
  int magic;

  oop_source *source;
  int fd;

  oop_call_line *call;
  void *state;

  size_t alloc;
  size_t pos;

  uint8_t buf[1];
};

static oop_line_file *
verify_line(oop_line *self)
{
  oop_line_file *line = (oop_line_file *) self;
  assert(line->magic == MAGIC);
  return line;
}

static void *
line_read(oop_source *source, int fd, oop_event event, void *state)
{
  oop_line_file *line = verify_line(state);
  
  void *value = OOP_CONTINUE;

  size_t to_read;
  int res;
  
  assert(event == OOP_READ);
  assert(line->source == source);
  assert(line->fd == fd);

  to_read = line->alloc - line->pos;

  assert(to_read > 0);

  do
    res = read(line->fd, line->buf + line->pos, to_read);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    {
      value = line->call(&line->oop, OOP_LINE_ERROR, 0, NULL, line->state);
    }
  else if (res == 0)
    {
      value = line->call(&line->oop, OOP_LINE_EOF, line->pos, line->buf, line->state);
      line->pos = 0;
    }
  else
    {
      uint8_t *eol = memchr(line->buf + line->pos, 0xa, res);
      if (eol)
	{
	  size_t length = eol - line->buf;

	  value = line->call(&line->oop, OOP_LINE_OK, length, line->buf, line->state);
	  length++;
	  line->pos = line->pos + res - length;

	  if (line->pos > 0)
	    memmove(line->buf, line->buf + length, line->pos);
	}
      else
	{
	  line->pos += res;
	  assert(line->pos <= line->alloc);

	  if (line->pos == line->alloc)
	    {
	      value = line->call(&line->oop, OOP_LINE_TOO_LONG,
				 line->alloc, line->buf, line->state);
	      line->pos = 0;
	    }
	}
    }
  if (value == OOP_LINE_DONE)
    {
      size_t length = line->pos;
      line->pos = 0;
      value = line->call(&line->oop, OOP_LINE_REST, length, line->buf, line->state);
    }
  return value;
}

static void
file_on_line(oop_line *self, oop_call_line call, void *state)
{
  oop_line_file *line = verify_line(self);

  line->call = call;
  line->state = state;

  line->source->on_fd(line->source, line->fd, OOP_READ, line_read, line);
}

static void
file_cancel_line(oop_line *self)
{
  oop_line_file *line = verify_line(self);

  line->call = NULL;
  line->state = NULL;

  line->source->cancel_fd(line->source, line->fd, OOP_READ);
}

oop_line_file *
oop_line_file_new(oop_source *source, int fd, size_t max)
{
  oop_line_file *line;

  assert(max > 0);
  line = malloc(sizeof(*line) - 1 + max);
  if (!line)
    return NULL;

  line->oop.on_line = file_on_line;
  line->oop.cancel_line = file_cancel_line;
  line->magic = MAGIC;

  line->source = source;
  line->fd = fd;

  line->call = NULL;
  line->state = NULL;

  line->alloc = max;
  line->pos = 0;

  return line;
}

void 
oop_line_file_delete(oop_line_file *line)
{
  assert(line->call == NULL);

  line->magic = 0;
  free(line);
}

oop_line *
oop_file_line(oop_line_file *line)
{
  return &line->oop;
}
