/* connection.h
 *
 */

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

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "abstract_io.h"
#include "abstract_compress.h"
#include "queue.h"
#include "resource.h"
#include "randomness.h"

/* Forward declaration */
struct ssh_connection;

#define GABA_DECLARE
#include "connection.h.x"
#undef GABA_DECLARE

/* This is almost a write handler; difference is that it gets an extra
 * argument with a connection object. */

/* GABA:
   (class
     (name packet_handler)
     (vars
       (handler method int
               "struct ssh_connection *connection"
	       "struct lsh_string *packet")))
*/

#define HANDLE_PACKET(closure, connection, packet) \
((closure)->handler((closure), (connection), (packet)))

#define CONNECTION_SERVER 0
#define CONNECTION_CLIENT 1

/* GABA:
   (class
     (name ssh_connection)
     (super abstract_write)
     (vars
       ; Sent and received version strings
       ;;(client_version string)
       ;;(server_version string)
       (versions array (string) 2)
       (session_id string)

       ; Cleanup
       (resources object resource_list)
       
       ; Receiving
       (rec_max_packet simple UINT32)
       (rec_mac    object mac_instance)
       (rec_crypto object crypto_instance)
       (rec_compress object compress_instance)

       ; Sending 
       (raw   object abstract_write)  ; Socket connected to the other end 
       (write object abstract_write)  ; Where to send packets through the
                                      ; pipeline.

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)

       ; Key exchange 
       (kex_state simple int)

       ; What to do once the connection is established
       (established object command_continuation)
       
       (kexinits array (object kexinit) 2)
       (literal_kexinits array (string) 2)

       ; Negotiated algorithms
       (newkeys object newkeys_info)
  
       ; Table of all known message types 
       (dispatch array (object packet_handler) "0x100");
       
       ; Table of all opened channels
       (channels object channel_table)
       
       ; Shared handlers 
       (ignore object packet_handler)
       (unimplemented object packet_handler)
       (fail object packet_handler)

       ; (provides_privacy simple int)
       ; (provides_integrity simple int)
       ))
*/

struct ssh_connection *make_ssh_connection(struct command_continuation *c);

void connection_init_io(struct ssh_connection *connection,
			struct abstract_write *raw,
			struct randomness *r);

struct packet_handler *make_fail_handler(void);
struct packet_handler *make_unimplemented_handler(void);  

#endif /* LSH_CONNECTION_H_INCLUDED */
