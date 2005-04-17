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

/* FIXME: Using ssh_read with it's limited buffer is actually not
   necessary. Could be rewritten to use a single buffer of size
   SSH_MAX_PACKET + 1 as output, which would also simplify the zlib
   inflation. */
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

void
transport_new_keys(struct transport_read_state *self,
		   struct mac_instance *mac, struct crypto_instance *crypto,
		   struct compress_instance *inflate);

#if 0
#include "ssh.h"

struct transport_read;

struct transport_read *
make_transport_read(void);

/* If fd >= 0, will try reading more data if needed, otherwise,
   processes only buffered data. Returns 1 on success, 0 if more data
   is needed, -1 for io errors, and -2 for protocol errors. On
   success, *length and *data gives the packet length and contents;
   contents is valid until the next call. At EOF, returns 1 and sets
   *line = NULL. */
int
transport_read_line(struct transport_read *self, int fd, int *error,
		    uint32_t *length, const uint8_t **line);

int
transport_read_packet(struct transport_read *self, int fd, int *error,
		      uint32_t *seqno,
		      uint32_t *length, const uint8_t **line);

struct transport_read
{
  enum { TRANSPORT_LINE, TRANSPORT_HEADER, TRANSPORT_PACKET, TRANSPORT_MAC } state;
  /* For fragments of lines and blocks. */
  uint8_t input[SSH_MAX_LINE];
  uint32_t input_pos;
  uint8_t output[SSH_MAX_PACKET + 1];
  uint32_t output_pos;

  uint32_t block_size;
  uint32_t length;
  uint32_t seqno;

  const uint8_t *error_msg;
};

void
transport_read_init(struct transport_read *self);

/* Switch to packet reading mode */
void
transport_read_packet(struct transport_read *self);

/* Returns 0 when a line or packet is complete, an SSH_DISCONNECT_*
   code on error, and -1 if more data is needed. */
int
transport_read_process(struct transport_read *self, uint32_t *done,
		       uint32_t length, const uint8_t *data);
#endif
#endif /* TRANSPORT_READ_H_INCLUDED */
