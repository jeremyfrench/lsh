/* disconnect.c
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

#include "disconnect.h"

#include "connection.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "xalloc.h"

struct lsh_string *format_disconnect(int code, char *msg)
{
  return ssh_format("%c%i%z%z",
		    SSH_MSG_DISCONNECT,
		    code,
		    msg, "");
}

static int do_disconnect(struct packet_handler *closure,
			 struct ssh_connection *connection,
			 struct lsh_string *packet)
{
  struct simple_buffer buffer;
  UINT8 msg;
  UINT32 length;
  UINT32 reason;
  UINT8 *start;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg)
      && (msg != SSH_MSG_DISCONNECT)
      && (parse_uint32(&buffer, &reason))
      && (parse_string(&buffer, &length, &start))
      /* FIXME: Language tag is ignored */ )
    {
      /* FIXME: Display message */
    }
  lsh_string_free(packet);
  
  /* FIXME: Mark the file as closed, somehow (probably a variable in
   * the write buffer) */

  return WRITE_CLOSED;
}

struct packet_handler *make_disconnect_handler()
{
  struct packet_handler *res =  xalloc(sizeof(struct packet_handler));

  res->handler = do_disconnect;
  return res;
}
