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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
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
   read buffer for each fd. Write buffers are larger, to avoid
   deadlock in the conversation with the remote peer. To stop buffers
   from filling up, whenever the write-buffer for the encrypted
   channel is getting full, we stop reading from the unencrypted
   channel, and vice versa.

   The write buffer for encrypted packets can also fill up with
   transport-layer packets generated in response to received encrypted
   packets. E.g, when receiving a KEXINIT message we need to reply to
   it directly; it is not passed to the application. We reserve buffer
   space of SSH_MAX_TRANSPORT_RESPONSE for such responses, and stop
   reading unencrypted data when less space than this is available in
   the buffer. If the buffer is filled up completely in spite of this
   margin, we disconnect.
*/

#ifndef LSH_TRANSPORT_H_INCLUDED
#define LSH_TRANSPORT_H_INCLUDED

#include "compress.h"
#include "crypto.h"
#include "keyexchange.h"
#include "resource.h"
#include "ssh_read.h"
#include "ssh_write.h"

struct transport_read_state;
struct transport_connection;

enum transport_event {
  /* Initial keyexchange complete, time to transmit or accept a
     service request */
  TRANSPORT_EVENT_KEYEXCHANGE_COMPLETE,
  /* Connection is being closed. */
  TRANSPORT_EVENT_CLOSE,
  /* Push through any buffered data; no more is arriving on the ssh
     connection. */
  TRANSPORT_EVENT_PUSH,
  /* Transport buffer non-empty, or key exchange in progress. New
     application data is not allowed. */
  TRANSPORT_EVENT_STOP_APPLICATION,
  /* Transport buffer empty again, new data is encouraged */
  TRANSPORT_EVENT_START_APPLICATION,
};

#define GABA_DECLARE
# include "transport.h.x"
#undef GABA_DECLARE

struct transport_read_state *
make_transport_read_state(void);

/* FIXME: 1. Some of more of this could perhaps be generalized to work
   with the service reader too. 2. It would be desirable to get the
   push indication together with the last read packet. To get that to
   work, the reader must be able to decrypt the next packet header. To
   do this, the handling of SSH_MSG_NEWKEYS must be moved down to the
   reader layer, which does make some sense. */

enum ssh_read_status
transport_read_line(struct transport_read_state *self, int fd,
		    int *error, const char **msg,
		    uint32_t *length, const uint8_t **line);

enum ssh_read_status
transport_read_packet(struct transport_read_state *self, int fd,
		      int *error, const char **msg,
		      uint32_t *seqno,
		      uint32_t *length, struct lsh_string *packet);

void
transport_read_new_keys(struct transport_read_state *self,
			struct mac_instance *mac,
			struct crypto_instance *crypto,
			struct compress_instance *inflate);


/* GABA:
   (class
     (name transport_write_state)
     (super ssh_write_state)
     (vars     
       ; The preferred packet size, and amount of data we try to
       ; collect before actually writing anything.
       (threshold . uint32_t)
       ; Amount of unimportant data at end of buffer
       (ignore . uint32_t)
       (mac object mac_instance)
       (crypto object crypto_instance)
       (deflate object compress_instance)
       (seqno . uint32_t)))
*/

/* Error codes are negative */
enum transport_write_status
{
  /* I/O error (see errno) */
  TRANSPORT_WRITE_IO_ERROR = -1,
  /* Buffer grew too large */
  TRANSPORT_WRITE_OVERFLOW = -2,
  /* All buffered data (except ignore data) written successfully. */
  TRANSPORT_WRITE_COMPLETE = 1,
  /* Buffered data still pending; call transport_write_flush. */
  TRANSPORT_WRITE_PENDING = 2
};

enum transport_write_flag
{
  TRANSPORT_WRITE_FLAG_PUSH = 1,
  TRANSPORT_WRITE_FLAG_IGNORE = 2,
};

struct transport_write_state *
make_transport_write_state(void);

enum transport_write_status
transport_write_packet(struct transport_write_state *self,
		       int fd, enum transport_write_flag flags,
		       struct lsh_string *packet);

enum transport_write_status
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
enum transport_write_status
transport_write_flush(struct transport_write_state *self,
		      int fd);

/* Fixed state used by all connections. */
/* GABA:
   (class
     (name transport_context)
     (vars
       (is_server . int)
       (algorithms object alist)
       (kexinit object kexinit_info)))
*/

void
init_transport_context (struct transport_context *self, int is_server);

/* Used for the key exchange method */

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
       ; The state for the receiving direction is reflected by kex.state
       (kex struct kexinit_state)
       
       (session_id string)
       ; Packet handler for the keyexchange range of messages
       (keyexchange_handler object transport_handler)
       ; New state to be taken into use after NEWKEYS
       (new_mac object mac_instance)
       (new_crypto object crypto_instance)
       (new_inflate object compress_instance)

       ; Timer for kexexchange, reexchange, and disconnect
       (expire object resource)

       ; Receiving encrypted packets
       ; Input fd for the ssh connection
       (ssh_input . int)
       (reader object transport_read_state)
       (read_active . int)
       ; Buffer for the latest read packet.
       (read_packet string)
       ; If non-zero, we should let the application process the
       ; previous packet again.
       (retry_length . uint32_t)
       (retry_seqno . uint32_t)
       
       ; Sending encrypted packets
       ; Output fd for the ssh connection, ; may equal ssh_input
       (ssh_output . int)
       (writer object transport_write_state)
       (write_active . int)
       ; Space we want to have left in the write buffer. We need space
       ; for one full packet, plus transport level responses such as
       ; KEXINIT, KEXDH_INIT, KEXDH_REPLY and UNIMPLEMENTED.
       (write_margin . uint32_t)
       
       ; If non-zero, it's the number of buffers that we are waiting on.
       (closing . unsigned)

       (event_handler method void "enum transport_event event")

       ; Handles all non-transport messages. Returns 1 on success, or
       ; 0 if the application's buffers are full. FIXME: Call should
       ; include a push indication.
       (packet_handler method int "uint32_t seqno" "uint32_t length"
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

void
transport_connection_kill(struct transport_connection *connection);

/* If flush is 1, try sending buffered data before closing. */
void
transport_close(struct transport_connection *self, int flush);

void
transport_send_packet(struct transport_connection *connection,
		      enum transport_write_flag flags, struct lsh_string *packet);

void
transport_write_pending(struct transport_connection *connection, int pending);

void
transport_start_read(struct transport_connection *connection);

void
transport_stop_read(struct transport_connection *connection);

void
transport_disconnect(struct transport_connection *connection,
		     int reason, const uint8_t *msg);

#define transport_protocol_error(connection, msg) \
  transport_disconnect((connection), SSH_DISCONNECT_PROTOCOL_ERROR, (msg))

void
transport_kexinit_handler(struct transport_connection *connection,
			  uint32_t length, const uint8_t *packet);

void
transport_send_kexinit(struct transport_connection *connection);

void
transport_keyexchange_finish(struct transport_connection *connection,
			     const struct nettle_hash *H,
			     struct lsh_string *exchange_hash,
			     struct lsh_string *K);

void
transport_handshake(struct transport_connection *connection,
		    struct lsh_string *version,
		    void (*line_handler)
		      (struct transport_connection *connection,
		       uint32_t length,
		       const uint8_t *line));

#endif /* LSH_TRANSPORT_H_INCLUDED */
