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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "debug.h"

#include "connection.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "xalloc.h"
#include "werror.h"

#include "debug.c.x"

/* GABA:
   (class
     (name packet_debug)
     (super abstract_write_pipe)
     (vars
       (prefix simple "const char *")))
*/

static void
do_debug(struct abstract_write *w,
	 struct lsh_string *packet,
	 struct exception_handler *e)
{
  CAST(packet_debug, closure, w);
  
  debug("DEBUG: received packet %xS\n", packet);
  
  A_WRITE(closure->super.next, packet, e);
}

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, const char *prefix)
{
  NEW(packet_debug, closure);

  closure->super.super.write = do_debug;
  closure->super.next = continuation;
  closure->prefix = prefix;

  return &closure->super.super;
}

static struct lsh_string *make_debug_packet(const char *msg, int always_display)
{
  return ssh_format("%c%c%z%z",
		    SSH_MSG_DEBUG,
		    always_display,
		    msg,
		    /* Empty language tag */ 
		    "");
}

/* Send a debug message to the other end. */
void send_debug(struct ssh_connection *connection, const char *msg, int always_display)
{
  if (debug_flag)
    C_WRITE(connection, make_debug_packet(msg, always_display));
}

void send_verbose(struct ssh_connection *connection, const char *msg, int always_display)
{
  if (verbose_flag)
    C_WRITE(connection, make_debug_packet(msg, always_display));
}

static void
do_rec_debug(struct packet_handler *self UNUSED,
	     struct ssh_connection *connection UNUSED,
	     struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  unsigned always_display;
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
      EXCEPTION_RAISE
	(connection->e,
	 make_protocol_exception(SSH_DISCONNECT_PROTOCOL_ERROR,
				 "Invalid DEBUG message."));
				 
    }
  else
    {
      if (always_display)
	werror("Received debug: %ups\n", length, msg);

      else
	verbose("Received debug: %ups\n", length, msg);
      
      lsh_string_free(packet);
    }
}

struct packet_handler *make_rec_debug_handler(void)
{
  NEW(packet_handler, self);

  self->handler = do_rec_debug;

  return self;
}
