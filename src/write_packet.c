/* write_packet.c */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2003 Niels Möller
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

#include "connection.h"
#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#include "write_packet.c.x"

/* GABA:
   (class
     (name write_packet)
     (super abstract_write_pipe)
     (vars
       (connection object ssh_connection)
       (random object randomness)
       (sequence_number . uint32_t)))
*/

static void
do_write_packet(struct abstract_write *s,
		struct lsh_string *packet)
{
  CAST(write_packet, self, s);
  struct ssh_connection *connection = self->connection;
  packet = encrypt_packet(packet,
			  connection->send_compress, connection->send_crypto,
			  connection->send_mac, self->random,
			  self->sequence_number++);
  A_WRITE(self->super.next, packet);
}

struct abstract_write *
make_write_packet(struct ssh_connection *connection,
		  struct randomness *random,
		  struct abstract_write *next)
{
  NEW(write_packet, self);
  self->super.super.write = do_write_packet;
  self->super.next = next;
  self->connection = connection;
  self->random = random;
  self->sequence_number = 0;

  return &self->super.super;
}
