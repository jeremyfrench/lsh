/* lshd.h
 *
 * Types used by the main server program.
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

#ifndef LSHD_H_INCLUDED
#define LSHD_H_INCLUDED

#include "abstract_io.h"
#include "kexinit.h"
#include "publickey_crypto.h"
#include "resource.h"
#include "ssh_read.h"
#include "ssh_write.h"

struct lshd_connection;

enum service_state
{
  /* Before key exchange, a service request is not acceptable. */
  SERVICE_DISABLED = 0,
  /* After key exchange, we accept a single service request. */
  SERVICE_ENABLED = 1,
  /* After the service is started, no more requests are allowed. */
  SERVICE_STARTED = 2
};

#define GABA_DECLARE
# include "lshd.h.x"
#undef GABA_DECLARE

/* FIXME: Could turn into a more general transport_read_state by
   moving the current decrypt and uncompress objects here, replacing
   the connection pointer. */
/* GABA:
   (class
     (name lshd_read_state)
     (super ssh_read_state)
     (vars
       (connection object lshd_connection)
       (sequence_number . uint32_t);
       (padding . uint8_t)))
*/

struct lshd_read_state *
make_lshd_read_state(struct lshd_connection *connection,
		     struct error_callback *error);

/* GABA:
   (class
     (name lshd_read_handler)
     (super abstract_write)
     (vars
       (connection object lshd_connection)))
*/

void
lshd_handle_packet(struct abstract_write *s, struct lsh_string *packet);

/* GABA:
   (class
     (name lshd_packet_handler)
     (vars
       ; Does *not* consume the packet
       (handler method void
                "struct lshd_connection *connection"
	        "struct lsh_string *packet")))
*/

#define HANDLE_PACKET(s, c, p) ((s)->handler((s), (c), (p)))

#define DEFINE_PACKET_HANDLER(NAME, CARG, PARG)	\
static void						\
do_##NAME(struct lshd_packet_handler *,			\
	  struct lshd_connection *,			\
	  struct lsh_string *);				\
							\
struct lshd_packet_handler NAME =			\
{ STATIC_HEADER, do_##NAME };				\
							\
static void						\
do_##NAME(struct lshd_packet_handler *s UNUSED,		\
	  struct lshd_connection *CARG,			\
	  struct lsh_string *PARG)


/* Information shared by several connections */
/* GABA:
   (class
     (name configuration)
     (vars
       (random object randomness)
       (algorithms object alist)
       (keys object alist)
       (kexinit object make_kexinit)
       ; For now, a list { name, program, name, program, NULL }       
       (services . "const char **")))
*/

/* GABA:
   (class
     (name lshd_connection)
     (super resource)
     (vars
       (config object configuration)
       
       ; Key exchange 
       (kex struct kexinit_state)
       
       (session_id string)

       (kexinit_handler object lshd_packet_handler)
       (newkeys_handler object lshd_packet_handler)
       ; Handler for all messages in the key exchange specific range
       (kex_handler object lshd_packet_handler)

       (service_state . "enum service_state")
       (service_handler object lshd_packet_handler)
       
       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)

       (reader object lshd_read_state)
       (rec_max_packet . uint32_t)
       (rec_mac object mac_instance)
       (rec_crypto object crypto_instance)
       (rec_compress object compress_instance)

       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       (writer object ssh_write_state)

       (send_mac object mac_instance)
       (send_crypto object crypto_instance)
       (send_compress object compress_instance)
       (send_seqno . uint32_t)
       
       ; Communication with service on top of the transport layer.
       ; This is a bidirectional pipe
       (service_fd . int)
       (service_reader object ssh_read_state)
       (service_writer object ssh_write_state)))
*/

void
lshd_handle_ssh_packet(struct lshd_connection *connection, struct lsh_string *packet);

void
connection_disconnect(struct lshd_connection *connection,
		      int reason, const uint8_t *msg);

void
connection_write_packet(struct lshd_connection *connection,
			struct lsh_string *packet);

#define connection_error(connection, msg) \
  connection_disconnect((connection), SSH_DISCONNECT_PROTOCOL_ERROR, (msg))

struct lshd_packet_handler *
make_lshd_dh_handler(struct dh_method *method);

extern struct lshd_packet_handler
lshd_kexinit_handler;

extern struct lshd_packet_handler
lshd_service_request_handler;

void
lshd_send_kexinit(struct lshd_connection *connection);

#endif /* LSHD_H_INCLUDED */
