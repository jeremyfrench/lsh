/* gateway.h
 *
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

#ifndef LSH_GATEWAY_H_INCLUDED
#define LSH_GATEWAY_H_INCLUDED

#include "lsh.h"

#include "connection.h"
#include "client.h"

#define GABA_DECLARE
#include "gateway.h.x"
#undef GABA_DECLARE

/* Formats the address of the local gateway socket. */

struct local_info *
make_gateway_address(const char *local_user, const char *remote_user,
		     const char *target);

/* Keeps track of one connection to the gateway. */

/* GABA:
   (class
     (name gateway_connection)
     (super ssh_connection)
     (vars
       ; Using the type client_connection rather than ssh_connection
       ; is needed for the handling of SSH_LSH_RANDOM_REQUEST.
       (shared object client_connection)

       ; The correspondign listening port. Needed when we are asked to close.
       (port object resource)

       (fd . int)
       (reader object service_read_state)
       (read_active . int)
       (writer object ssh_write_state)
       ; Means we have an active write callback.
       (write_active . int)))
*/

/* Sends raw data (used for hello message). Returns errno value or
   zero on success. */
int
gateway_write_data(struct gateway_connection *connection,
		   uint32_t length, const uint8_t *data);

void
gateway_write_packet(struct gateway_connection *connection,
		     struct lsh_string *packet);

void
gateway_start_read(struct gateway_connection *self);

void
gateway_stop_read(struct gateway_connection *self);

struct gateway_connection *
make_gateway_connection(struct client_connection *shared,
			struct resource *port, int fd);

struct resource *
make_gateway_port(const struct local_info *local,
		  struct client_connection *connection);

int
gateway_forward_channel(struct ssh_connection *target_connection,
			const struct channel_open_info *info,
			uint32_t arg_length, const uint8_t *arg);

extern struct channel_open gateway_channel_open;

#endif /* LSH_GATEWAY_H_INCLUDED */
