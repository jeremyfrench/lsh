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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_CONNECTION_H_INCLUDED
#define LSH_CONNECTION_H_INCLUDED

#include "abstract_io.h"
#include "randomness.h"

/* Forward declaration */
struct ssh_connection;

#define CLASS_DECLARE
#include "connection.h.x"
#undef CLASS_DECLARE

/* This is almost a write handler; difference is that it gets an extra
 * argument with a connection object. */

/* CLASS:
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

/* CLASS:
   (class
     (name ssh_connection)
     (super abstract_write)
     (vars
       ; Sent and recieved version strings
       (client_version string)
       (server_version string)
       (session_id string)

       ; Recieveing
       (rec_max_packet simple UINT32)
       (rec_mac    object mac_instance)
       (rec_crypto object crypto_instance)

       ; Sending 
       (raw   object abstract_write)  ; Socket connected to the other end 
       (write object abstract_write)  ; Where to send packets through the
                                      ; pipeline.

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)

       ; Key exchange 
       (kex_state simple int)
  
       ; (simple make_kexinit make_kexinit)

       (kexinits array (object kexinit) 2)
       ;;;  struct kexinit *kexinits[2];
       (literal_kexinits array (string) 2)
       ;;; struct lsh_string *literal_kexinits[2];

       ; Negotiated algorithms
       (newkeys object newkeys_info)
  
       ; Table of all known message types 
       (dispatch array (object packet_handler) "0x100");

       ; Shared handlers 
       (ignore object packet_handler)
       (unimplemented object packet_handler)
       (fail object packet_handler)

       ; (provides_privacy simple int)
       ; (provides_integrity simple int)
       ))
*/

struct ssh_connection *make_ssh_connection(struct packet_handler *kex_handler);
void connection_init_io(struct ssh_connection *connection,
			struct abstract_write *raw,
			struct randomness *r);

struct packet_handler *make_fail_handler(void);
struct packet_handler *make_unimplemented_handler(void);  

#endif /* LSH_CONNECTION_H_INCLUDED */
