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
       (shared object ssh_connection)
       (fd . int)
       (reader object service_read_state)
       (writer object ssh_write_state)))
*/

struct gateway_connection *
make_gateway_connection(struct ssh_connection *shared, int fd);

int
gateway_packet_handler(struct gateway_connection *connection,
		       uint32_t length, const uint8_t *packet);


#endif /* LSH_GATEWAY_H_INCLUDED */
