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


#define GABA_DECLARE
#include "connection.h.x"
#undef GABA_DECLARE

/* This is almost a write handler; difference is that it gets an extra
 * argument with a connection object. */

/* GABA:
   (class
     (name packet_handler)
     (vars
       (handler method void
               "struct ssh_connection *connection"
	       "struct lsh_string *packet")))
*/

#define HANDLE_PACKET(closure, connection, packet) \
((closure)->handler((closure), (connection), (packet)))

#define CONNECTION_SERVER 0
#define CONNECTION_CLIENT 1

#define PEER_SSH_DSS_KLUDGE           0x00000001
#define PEER_SERVICE_ACCEPT_KLUDGE    0x00000002
#define PEER_USERAUTH_REQUEST_KLUDGE  0x00000004
#define PEER_SEND_NO_DEBUG            0x00000008
#define PEER_X11_OPEN_KLUDGE          0x00000010

/* GABA:
   (class
     (name ssh_connection)
     (super abstract_write)
     (vars
       ; Where to pass errors
       (e object exception_handler)

       ; Sent and received version strings
       (versions array (string) 2)
       (session_id string)
       
       ; Connection description, used for debug messages.
       (debug_comment simple "const char *")

       ; Features or bugs peculiar to the peer
       (peer_flags simple UINT32)
       
       ; the chained connection in the proxy
       (chain object ssh_connection)

       ; Cleanup
       (resources object resource_list)

       ; Connected peer
       ; FIXME: Perhaps this should be a sockaddr or some other object
       ; that facilitates reverse lookups?
       (peer object address_info);
       
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

       ; For operations that require serialization. In particular
       ; the server side of user authentication.
       
       ; To handle this intelligently, we should stop reading from the
       ; socket, and/or put received packets on a wait queue.

       ; Currently, we don't do anything like that, we use this flag
       ; for sanity checks, and relies on the functions setting the flag
       ; to clear it before returning to the main loop.
       (busy . int)
       
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
       (table object channel_table)
       
       ; Shared handlers 
       (ignore object packet_handler)
       (unimplemented object packet_handler)
       (fail object packet_handler)

       ; (provides_privacy simple int)
       ; (provides_integrity simple int)
       )) */

#define C_WRITE(c, s) A_WRITE((c)->write, (s) )

struct ssh_connection *
make_ssh_connection(struct address_info *peer,
		    const char *id_comment,
		    struct command_continuation *c,
		    struct exception_handler *e);

struct exception_handler *
make_exc_protocol_handler(struct ssh_connection *connection,
			  struct exception_handler *parent,
			  const char *context);

void connection_init_io(struct ssh_connection *connection,
			struct abstract_write *raw,
			struct randomness *r);

/* Serialization */
void connection_lock(struct ssh_connection *self);
void connection_unlock(struct ssh_connection *self);

/* Table of packet types */
extern const char *packet_types[0x100];

#endif /* LSH_CONNECTION_H_INCLUDED */
