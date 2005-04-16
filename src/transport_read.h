/* transport_read.h
 *
 * Reading the ssh transport protocol.
 *
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

#ifndef TRANSPORT_READ_H_INCLUDED
#define TRANSPORT_READ_H_INCLUDED

#include "abstract_crypto.h"
#include "ssh_read.h"

#define GABA_DECLARE
# include "transport_read.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name transport_read_state)
     (super ssh_read_state)
     (vars
       (max_packet . uint32_t)
       (mac object mac_instance)
       (crypto object crypto_instance)
       (compression object compress_instance)

       (sequence_number . uint32_t);
       (padding . uint8_t)

       ; Called for protocol errors. reason is one of the
       ; SSH_DISCONNECT_* values, or zero if no disconnect message
       ; should be sent.       
       (protocol_error method void "int reason" "const char *msg")
       ; Handler for decrypted packets
       (handle_packet method void "struct lsh_string *")))
*/

void
init_transport_read_state(struct transport_read_state *self,
			  uint32_t max_packet,
			  void (*io_error)(struct ssh_read_state *state, int error),
			  void (*protocol_error)
			    (struct transport_read_state *state, int reason, const char *msg));

struct transport_read_state *
make_transport_read_state(uint32_t max_packet,
			  void (*io_error)(struct ssh_read_state *state, int error),
			  void (*protocol_error)
			    (struct transport_read_state *state, int reason, const char *msg));

void
transport_read_packet(struct transport_read_state *self,
		      oop_source *source, int fd,
		      void (*handle_packet)
		        (struct transport_read_state *state, struct lsh_string *packet));
		      
#endif /* TRANSPORT_READ_H_INCLUDED */
