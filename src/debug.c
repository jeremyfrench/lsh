/* debug.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "debug.h"

#include "connection.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "xalloc.h"
#include "werror.h"

struct packet_debug
{
  struct abstract_write_pipe super;
  char *prefix;
};

static int do_debug(struct abstract_write **w,
		    struct lsh_string *packet)
{
  struct packet_debug *closure
    = (struct packet_debug *) *w;
  
  MDEBUG(closure);

  debug("DEBUG: recieved packet");
  debug_hex(packet->length, packet->data);
  debug("\n");
  
  return A_WRITE(closure->super.next, packet);
}

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, char *prefix)
{
  struct packet_debug *closure = xalloc(sizeof(struct packet_debug));

  closure->super.super.write = do_debug;
  closure->super.next = continuation;
  closure->prefix = prefix;

  return &closure->super.super;
}

static struct lsh_string *make_debug_packet(char *msg, int always_display)
{
  return ssh_format("%c%c%z%z",
		    SSH_MSG_DEBUG,
		    always_display,
		    msg,
		    /* Empty language tag */ 
		    "");
}

/* Send a debug message to the other end. */
int send_debug(struct abstract_write *write, char *msg, int always_display)
{
  return (debug_flag)
    ? A_WRITE(write, make_debug_packet(msg, always_display))
    : WRITE_OK;
  
}

int send_verbose(struct abstract_write *write, char *msg, int always_display)
{
  return (verbose_flag)
    ? A_WRITE(write, make_debug_packet(msg, always_display))
    : WRITE_OK;
}

static int do_rec_debug(struct packet_handler *self,
			struct ssh_connection *connection,
			struct lsh_string *packet)
{
  struct simple_buffer buffer;
  UINT8 msg_number;
  UINT8 always_display;
  UINT32 length;
  UINT8 *msg;
  int language;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!(parse_uint8(&buffer, &msg_number)
	&& parse_uint8(&buffer, &always_display)
	&& parse_string(&buffer, &length, &msg)
	&& parse_atom(&buffer, &language)
	&& parse_eod(&buffer)))
    {
      lsh_string_free(packet);
      return WRITE_CLOSED;
    }

  if (always_display)
    {
      werror("Recieved debug: ");
      werror_utf8(length, msg);
      werror("\n");
    }
  else
    {
      verbose("Recieved debug: ");
      verbose_utf8(length, msg);
      verbose("\n");
    }

  lsh_string_free(packet);
  return WRITE_OK;
}

struct packet_handler *make_rec_debug_handler(void)
{
  struct packet_handler *self = xalloc(sizeof(struct packet_handler));

  self->handler = do_rec_debug;

  return self;
}
