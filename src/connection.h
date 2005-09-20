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

enum {
  /* Values used in the in_use array. */
  CHANNEL_FREE = 0,
  CHANNEL_RESERVED = 1,
  CHANNEL_IN_USE = 2,
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

       ; Used for unknown requests unknown channel types.
       (open_fallback object channel_open)
       
       ; Allocation of local channel numbers is managed using the same
       ; method as is traditionally used for allocation of unix file 
       ; descriptors.

       ; A channel number can be reserved before there is any actual
       ; channel object created for it. In particular, this is the
       ; case for channel numbers allocated bythe CHANNEL_OPEN
       ; handler. So the channels table is not enough for keeping
       ; track of which numbers are in use.       
       (in_use space uint8_t)

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

       ; Forwarded TCP ports. FIXME: Do we really need two of them?
       (local_ports struct object_queue)
       (remote_ports struct object_queue)

       ; Used if we're currently forwarding X11. To support several
       ; screens at the same time, this should be replaced with a
       ; list, analogous to the remote_ports list above. Perhaps it
       ; could be moved to the lcient side subclass?       
       (x11_display object client_x11_display)
       
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
ssh_connection_alloc_channel(struct ssh_connection *connection);

void
ssh_connection_dealloc_channel(struct ssh_connection *connection, uint32_t i);

void
ssh_connection_use_channel(struct ssh_connection *connection,
			   uint32_t local_channel_number);

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

struct channel_open_info
{
  uint32_t type_length;

  /* NOTE: This is a pointer into the packet, so if it is needed later
   * it must be copied. */
  const uint8_t *type_data;
  
  int type;

  uint32_t remote_channel_number;
  uint32_t send_window_size;
  uint32_t send_max_packet;
};

struct exception *
make_channel_open_exception(uint32_t error_code, const char *msg);

/* GABA:
   (class
     (name channel_open)
     (vars
       (handler method void
                "struct ssh_connection *connection"
		"struct channel_open_info *info"
                "struct simple_buffer *data"
                "struct command_continuation *c"
		"struct exception_handler *e")))
*/

#define CHANNEL_OPEN(o, c, i, d, r, e) \
((o)->handler((o), (c), (i), (d), (r), (e)))

#define DEFINE_CHANNEL_OPEN(name)			\
static void do_##name(struct channel_open *s,		\
		      struct ssh_connection *c,	\
		      struct channel_open_info *info,	\
		      struct simple_buffer *args,	\
		      struct command_continuation *c,	\
		      struct exception_handler *e);	\
							\
struct channel_open name =				\
{ STATIC_HEADER, do_##name };				\
							\
static void do_##name

extern struct command_2 connection_remember;
#define CONNECTION_REMEMBER (&connection_remember.super.super)

#endif /* LSH_CONNECTION_H_INCLUDED */
