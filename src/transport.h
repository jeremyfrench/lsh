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

/* The transport layer, for both server (lshd) and client
   (lsh-transport), speaks the ssh protocol on one end (two fd:s), and
   clear-text ssh packets on the other end.
   
    --------+           +-----------+           +--------
            |  -------> | SSH       | --------> |
    Network |    SSH    | transport | Cleartext | Application
            |  <------- | protocol  | <-------- |
    --------+           +-----------+           +--------

   We use non-blocking mode for i/o, with essentially a single-packet
   read buffer for each fd. Write buffers must be larger, to avoid
   deadlock in the conversation with the remote peer. To stop buffers
   from filling up, whenever the write-buffer for the encrypted
   channel is non-empty, we stop reading from the unencrypted channel,
   and vice versa.

   If either write buffer fills up completely, the connection is
   closed. This can happen if the application or the remote peer
   requests a lot of data, but doesn't read any.
*/

#ifndef TRANSPORT_H_INCLUDED
#define TRANSPORT_H_INCLUDED

#include <oop.h>

#include "abstract_crypto.h"
#include "compress.h"
#include "kexinit.h"
#include "resource.h"

struct transport_read_state;
struct transport_write_state;
struct transport_connection;

enum transport_event {
  /* Initial keyexchange complete, time to transmit or accept a
     service request */
  TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE,
  /* Disconnect message received */
  TRANSPORT_EVENT_DISCONNECT,
  /* Transport buffer non-empty, new data is discouraged */  
  TRANSPORT_EVENT_STOP_APPLICATION,
  /* Transport buffer empty again, new data is encouraged */
  TRANSPORT_EVENT_START_APPLICATION,
};

#define GABA_DECLARE
# include "transport.h.x"
#undef GABA_DECLARE

struct transport_read_state *
make_transport_read_state(void);

int
transport_read_line(struct transport_read_state *self, int fd,
		    int *error, const char **msg,
		    uint32_t *length, const uint8_t **line);

int
transport_read_packet(struct transport_read_state *self, int fd,
		      int *error, const char **msg,
		      uint32_t *seqno,
		      uint32_t *length, const uint8_t **data);

void
transport_read_new_keys(struct transport_read_state *self,
			struct mac_instance *mac,
			struct crypto_instance *crypto,
			struct compress_instance *inflate);


struct transport_write_state *
make_transport_write_state(void);

int
transport_write_packet(struct transport_write_state *self, int fd, int flush,
		       struct lsh_string *packet, struct randomness *random);

int
transport_write_line(struct transport_write_state *self,
		     int fd,
		     struct lsh_string *line);

void
transport_write_new_keys(struct transport_write_state *self,
			 struct mac_instance *mac,
			 struct crypto_instance *crypto,
			 struct compress_instance *deflate);

/* Attempt to send pending data, and maybe add an extra SSH_MSG_IGNORE
   packet */
int
transport_write_flush(struct transport_write_state *self, int fd);

/* Fixed state used by all connections. */
/* GABA:
   (class
     (name transport_context)
     (vars
       (random object randomness)
       (algorithms object alist)
       (kexinit object make_kexinit)
       (oop . "oop_source *")))
*/

/* Use primarily for the key exchange method */

/* GABA:
   (class
     (name transport_handler)
     (vars
       (handler method void
		       "struct transport_connection *connection"
		       "uint32_t length" "const uint8_t *packet")))
*/


/* GABA:
   (class
     (name transport_connection)
     (super resource)
     (vars
       (ctx object transport_context)

       ; Key exchange 
       (kex struct kexinit_state)
       (session_id string)
       ; Packet handler for the keyexchange range of messages
       (keyexchange_handler object transport_handler)
       (new_mac object mac_instance)
       (new_crypto object crypto_instance)
       (new_compress object compress_instance)

       ; Timer for key reexchange and kexexchange timeout
       (timeout object resource)

       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)
       (reader object transport_read_state)
       
       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       (writer object transport_write_state)
       (write_pending . int)
       
       (event_handler method void "enum transport_event event")
       ; Handles all non-transport messages
       (packet_handler method void "uint32_t length"
                                   "const uint8_t *packet")
       (line_handler method void "uint32_t length"
                                 "const uint8_t *line")))
*/

void
init_transport_connection(struct transport_connection *self,
			  void (*kill)(struct resource *s),
			  struct transport_context *ctx,
			  int ssh_input, int ssh_output,
			  void (*event)(struct transport_connection *,
					enum transport_event event));

/* If flush is 1, try sending buffered data before closing. */
void
transport_close(struct transport_connection *self, int flush);

void
transport_send_packet(struct transport_connection *connection, struct lsh_string *packet);

void
transport_write_pending(struct transport_connection *connection, int pending);

void
transport_disconnect(struct transport_connection *connection,
		     int reason, const uint8_t *msg);

#define transport_protocol_error(connection, msg) \
  transport_disconnect((connection), SSH_DISCONNECT_PROTOCOL_ERROR, (msg))

void
transport_kexinit_handler(struct transport_connection *connection,
			  uint32_t length, const uint8_t *packet);

#endif /* TRANSPORT_H_INCLUDED */
