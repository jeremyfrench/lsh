/* proxy_x11forward.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "proxy_x11forward.h"

#include "gateway_channel.h"
#include "xalloc.h"
#include "ssh.h"
#include "werror.h"
#include "channel_commands.h"
#include "format.h"

#define WINDOW_SIZE 10000

static void
do_proxy_open_x11(struct channel_open *s UNUSED,
		  struct ssh_connection *connection,
		  struct channel_open_info *info,
		  struct simple_buffer *args,
		  struct command_continuation *c,
		  struct exception_handler *e)
{
  struct lsh_string *host = NULL;
  uint32_t port = 0;

  if ((host = parse_string_copy(args)) &&
      parse_uint32(args, &port) &&
      parse_eod(args))
    {
      struct gateway_channel *server
	= make_gateway_channel(NULL);

      struct command *o;
 
      /* NOTE: The origin's rec_window_size and rec_max_packet becomes
       * the target's send_window_size and send_max_packet. */
      /* FIXME: maybe parse the sent string to get the port value */
      o = make_gateway_channel_open_command(info,
					    ssh_format("%S%i",
						       host, port), 
					    NULL);
      if (port)
	werror("x11 open request: host=%S:%i\n", host, port);
      else
	werror("datafellows compatible x11 open request: %S\n", host);
      COMMAND_CALL(o,
		   connection->chain,
		   make_gateway_channel_open_continuation(c, NULL, server),
		   e);

    }
  else
    PROTOCOL_ERROR(e, "Trailing garbage in open message");
}

struct channel_open *
make_proxy_open_x11(void)
{
  NEW(channel_open, self);

  self->handler = do_proxy_open_x11;
  return self;
}

