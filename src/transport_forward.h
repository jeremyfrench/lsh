/* transport_forward.h
 *
 * Uses the transport protocol and forwards unecrypted packets to and
 * from other fd:s.
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

#include "service.h"
#include "transport.h"

#define GABA_DECLARE
# include "transport_forward.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name transport_forward)
     (super transport_connection)
     (vars
       ; Communication with service on top of the transport layer.
       (service_in . int)
       (service_reader object service_read_state)
       (service_read_active . int)

       (service_out . int)
       (service_writer object ssh_write_state)
       (service_write_active . int)))
*/

void
init_transport_forward(struct transport_forward *self,
		       void (*kill)(struct resource *s),
		       struct transport_context *ctx,
		       int ssh_input, int ssh_output,
		       int (*event)(struct transport_connection *,
				    enum transport_event event));

struct transport_forward *
make_transport_forward(void (*kill)(struct resource *s),
		       struct transport_context *ctx,
		       int ssh_input, int ssh_output,
		       int (*event)(struct transport_connection *,
				    enum transport_event event));

void
transport_forward_kill(struct transport_forward *self);

/* Sets up event_handler and packet_handler to forward cleartext
   packets to the service layer. */
void
transport_forward_setup(struct transport_forward *self,
			int service_in, int service_out);
