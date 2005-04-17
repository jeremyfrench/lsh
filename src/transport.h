/* transport.h
 *
 * Interface for the ssh transport protocol.
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

#ifndef TRANSPORT_H_INCLUDED
#define TRANSPORT_H_INCLUDED

#define GABA_DECLARE
# include "transport.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name keyexchange_output)
     (vars
       (H object hash_algorithm)
       (exchange_hash string)
       (K string)))
*/

/* GABA:
   (class
     (name keyexchange_handler)
     (vars
       (handler method "struct keyexchange_output *"
                       "struct transport_connection *connection"
		       "struct lsh_string *packet")))
*/

/* GABA:
   (class
     (name transport_connection)
     (super resource)
     (vars
       (random object randomness)
       (algorithms object alist)

       ; Key exchange 
       (kex struct kexinit_state)
       (session_id string)
       ; Packet handler for the keyexchange range of messages
       (keyexchange_handler object transport_packet_handler)
       
       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)
       (reader object transport_read_state)

       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       (writer object ssh_write_state)

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)
       (send_seqno . uint32_t)

       ; Handles all non-transport messages
       (handler method void "struct lsh_string *")))
*/

/* GABA:
   (class
     (name transport_packet_handler)
     (vars
       (handle method void "struct lsh_string *")))
*/

void
init_transport_connection(struct transport_connection *self,
			  struct randomness *random, struct algorithms *algorithms,
			  int ssh_input, int ssh_output,
			  void (*handler)(struct transport_connection *connection,
					  struct lsh_string *packet));

void
kill_transport_close(struct transport_connection *self)

void
transport_write_data(struct transport_connection *connection, struct lsh_string *data);

void
transport_write_packet(struct transport_connection *connection, struct lsh_string *packet);

void
transport_disconnect(struct transport_connection *connection,
		     int reason, const uint8_t *msg);

#define transport_protocol_error(connection, msg) \
  transport_disconnect((connection), SSH_DISCONNECT_PROTOCOL_ERROR, (msg))


#endif /* TRANSPORT_H_INCLUDED */
