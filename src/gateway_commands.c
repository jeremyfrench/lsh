/* gateway_commands.c
 *
 * $Id$
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

/* FIXME: Same vars as connection_remember_command */
/* GABA:
   (class
     (name gateway_accept_command)
     (super command)
     (vars
       (connection object ssh_connection)))
*/

static void
do_gateway_accept(struct command *s,
		  struct lsh_object *x,
		  struct command_continuation *c,
		  struct exception_handler *e UNUSED)
{
  CAST(gateway_accept_command, self, s);
  CAST(listen_value, lv, x);

  struct ssh_connection *connection
    = make_ssh_connection(0, /* flags */
			  lv->peer, "gateway",
			  NULL, /* established_continuation */
			  make_exc_finish_read_handler(lv->fd, e, HANDLER_CONTEXT));

  connection->raw
    = &io_read_write(lv->fd,
		     make_buffered_read
		     (BUF_SIZE,
		      make_read_packet(connection, &connection->super)),
		     self->info->block_size,
		     make_connection_close_handler(connection));
}
