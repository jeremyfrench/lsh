/* connection.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Niels Möller
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

#include "exception.h"
#include "parse.h"
#include "queue.h"
#include "resource.h"

struct channel_open;
struct channel_open_info;

enum channel_alloc_state {
  /* Values used in the alloc_flags array. */
  CHANNEL_FREE = 0,
  CHANNEL_ALLOC_SENT_OPEN,
  CHANNEL_ALLOC_RECEIVED_OPEN,
  CHANNEL_ALLOC_ACTIVE,
};

#define GABA_DECLARE
#include "connection.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name ssh_connection)
     (super resource)
     (vars
       ; Communication with the transport layer
       (write method void "struct lsh_string *")
       (disconnect method void "uint32_t reason" "const char *msg")

       ; Resources associated with the connection, including the channels.
       (resources object resource_list)
       
       ; Channels are indexed by local number
       (channels space (object ssh_channel) used_channels)
       
       ; Global requests that we support
       (global_requests object alist)
       ; Channel types that we can open
       (channel_types object alist)
       ; If non-NULL, invoked for unknown channel types.
       (open_fallback object channel_open)

       ; Allocation of local channel numbers is managed using the same
       ; method as is traditionally used for allocation of unix file 
       ; descriptors.

       ; A channel number can be reserved before there is any actual
       ; channel object created for it. In particular, this is the
       ; case for channel numbers allocated by the CHANNEL_OPEN
       ; handler. So the channels table is not enough for keeping
       ; track of which numbers are in use.       
       (alloc_state space "enum channel_alloc_state")

       ; Allocated size of the arrays.
       (allocated_channels . uint32_t)

       ; Number of entries in the arrays that are in use and
       ; initialized.
       (used_channels . uint32_t)

       ; The smallest channel number that is likely to be free
       (next_channel . uint32_t)

       ; Number of currently allocated channel numbers.
       (channel_count . uint32_t)
       
       (max_channels . uint32_t) ; Max number of channels allowed 

       ; Forwarded TCP ports. On the server side, it's ports we listen
       ; on. On the client side, it's remote ports for which we have
       ; requested forwarding, and expect to get receive CHANNEL_OPEN
       ; forwarded-tcpip requests on.       
       (forwarded_ports struct object_queue)

       ; Global requests that we have received, and should reply to
       ; in the right order
       (active_global_requests struct object_queue)

       ; Queue of global requests that we expect replies on.
       (pending_global_requests struct object_queue)
       
       ; If non-zero, close connection after all active channels have
       ; died, and don't allow any new channels to be opened.
       (pending_close . int)))
*/

#define SSH_CONNECTION_WRITE(c, s) ((c)->write((c), (s)))
#define SSH_CONNECTION_DISCONNECT(c, r, msg) ((c)->disconnect((c), (r), (msg)))
#define SSH_CONNECTION_ERROR(c, msg) \
  SSH_CONNECTION_DISCONNECT((c), SSH_DISCONNECT_PROTOCOL_ERROR, (msg))

void
init_ssh_connection(struct ssh_connection *table,
		    void (*kill)(struct resource *),
		    void (*write)(struct ssh_connection *, struct lsh_string *),
		    void (*disconnect)(struct ssh_connection *, uint32_t, const char *));

void
ssh_connection_pending_close(struct ssh_connection *table);

int
ssh_connection_alloc_channel(struct ssh_connection *connection,
			     enum channel_alloc_state type);

void
ssh_connection_dealloc_channel(struct ssh_connection *connection,
			       uint32_t local_channel_number);
void
ssh_connection_register_channel(struct ssh_connection *connection,
				uint32_t local_channel_number,
				struct ssh_channel *channel);
void
ssh_connection_activate_channel(struct ssh_connection *connection,
				uint32_t local_channel_number);

struct ssh_channel *
ssh_connection_lookup_channel(struct ssh_connection *connection,
			      uint32_t local_channel_number,
			      enum channel_alloc_state flag);

void
ssh_connection_foreach(struct ssh_connection *connection,
		       void (*f)(struct ssh_channel *));

void
ssh_connection_stop_channels(struct ssh_connection *connection);

void
ssh_connection_start_channels(struct ssh_connection *connection);



/* SSH_MSG_GLOBAL_REQUEST */

/* GABA:
   (class
     (name global_request)
     (vars
       (handler method void "struct ssh_connection *table"
                            "uint32_t type"
			    ; want-reply is needed only by
			    ; do_gateway_global_request.
                            "int want_reply"
                            "struct simple_buffer *args"
			    "struct command_continuation *c"
			    "struct exception_handler *e")))
*/

#define GLOBAL_REQUEST(r, c, t, w, a, n, e) \
((r)->handler((r), (c), (t), (w), (a), (n), (e)))

/* SSH_MSG_CHANNEL_OPEN */

/* FIXME: Move definitions to channel.h?. */
/* GABA:
   (class
     (name channel_open_info)
     (vars
       (connection object ssh_connection)
       (local_channel_number . uint32_t)

       ;; NOTE: This is a pointer into the packet, and valid only during the call to the
       ;; channel open method.
       (type_length . uint32_t)
       (type_data . "const uint8_t *")
       (type . int)

       (remote_channel_number . uint32_t)
       (send_window_size . uint32_t)
       (send_max_packet . uint32_t)))
*/

/* GABA:
   (class
     (name channel_open)
     (vars
       (handler method void
		"const struct channel_open_info *info"
                "struct simple_buffer *data")))
*/

#define CHANNEL_OPEN(o, i, d) \
((o)->handler((o), (i), (d)))

#define DEFINE_CHANNEL_OPEN(name)				\
static void do_##name(struct channel_open *s,			\
		      const struct channel_open_info *info,	\
		      struct simple_buffer *args);		\
								\
struct channel_open name =					\
{ STATIC_HEADER, do_##name };					\
								\
static void do_##name


#endif /* LSH_CONNECTION_H_INCLUDED */
