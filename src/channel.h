/* channel.h
 *
 * Information about ssh channels.
 *
 * $Id$
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

#ifndef LSH_CHANNEL_H_INCLUDED
#define LSH_CHANNEL_H_INCLUDED

#include "alist.h"
#include "command.h"
#include "connection.h"
#include "parse.h"
#include "server_pty.h"

#define GABA_DECLARE
#include "channel.h.x"
#undef GABA_DECLARE

/* Channels are indexed by local channel number in some array. This
 * index is not stored in the channel struct. When sending messages on
 * the channel, it is identified by the *remote* sides index number,
 * and this number must be stored. */

#define CHANNEL_DATA 0
#define CHANNEL_STDERR_DATA 1

#define CHANNEL_SENT_CLOSE 1
#define CHANNEL_RECEIVED_CLOSE 2
#define CHANNEL_SENT_EOF 4
#define CHANNEL_RECEIVED_EOF 8

/* Means that we should send close when we have both sent and received EOF. */
#define CHANNEL_CLOSE_AT_EOF 0x10


/* GABA:
   (class
     (name ssh_channel)
     (vars
       ; Remote channel number 
       (channel_number simple UINT32)

       ; We try to keep the rec_window_size between max_window / 2
       ; and max_window.
       (max_window simple UINT32)       

       (rec_window_size simple UINT32)
       (rec_max_packet simple UINT32)

       (send_window_size simple UINT32)
       (send_max_packet simple UINT32)

       ; FIXME: Perhaps this should be moved to the channel_table, and
       ; a pointer to that table be stored here instead?
       ; Now that we pass the connection pointer to most functions,
       ; is this field needed at all?
       (write object abstract_write)
  
       (request_types object alist)

       (flags simple int)

       ; Number of files connected to this channel. For instance,
       ; stdout and stderr can be multiplexed on the same channel. We
       ; should not close the channel until we have got an EOF on both
       ; sources.
       (sources simple int)

       ; FIXME: What about return values from these functions? A
       ; channel may fail to process it's data. Is there some way to
       ; propagate a channel broken message to the other end? 

       ; Type is CHANNEL_DATA or CHANNEL_STDERR_DATA
       (receive method int "int type" "struct lsh_string *data")

       ; Called when we are allowed to send data on the channel. 
       (send method int)

       ; Called when the channel is closed
       ; FIXME: Is this needed for anything?
       (close method int)

       ; Called when eof is received on the channel (or when it is
       ; closed, whatever happens first).
       (eof method int)
  
       ; Reply from SSH_MSG_CHANNEL_OPEN_REQUEST
       ;; (open_confirm method int)
       ;; (open_failure method int)
       (open_continuation object command_continuation)

       ; Queue of channel requests that we expect replies on
       (pending_requests struct object_queue)))
       
       ; Reply from SSH_MSG_CHANNEL_REQUEST 
       ;; (channel_success method int)
       ;; (channel_failure method int)))
*/

#define CHANNEL_RECEIVE(s, t, d) \
((s)->receive((s), (t), (d)))

#define CHANNEL_SEND(s) ((s)->send((s)))
     
#define CHANNEL_CLOSE(s) \
((s)->close((s)))

#define CHANNEL_EOF(s) \
((s)->eof((s)))

#define CHANNEL_OPEN_CONFIRM(s) \
((s)->open_confirm((s)))

#define CHANNEL_OPEN_FAILURE(s) \
((s)->open_failure((s)))

     
/* FIXME: Perhaps, this information is better kept in the connection
 * object? */

/* GABA:
   (class
     (name channel_table)
     (vars
       ; FIXME: This is relevant only for the server side. It's
       ; probably better to store this in the connection struct.

       ;; uid_t user;  ; Authenticated user 

       ; Channels are indexed by local number
       (channels pointer (object ssh_channel) used_channels)

       ; Allocation of local channel numbers is managed using the same
       ; method as is traditionally used for allocation of unix file 
       ; descriptors.

       (allocated_channels simple UINT32)
       (next_channel simple UINT32)
     
       (used_channels simple UINT32)
       (max_channels simple UINT32) ; Max number of channels allowed 

       ; Global requests that we have received, and should reply to
       ; in the right order
       (active_global_requests struct object_queue)

       ; Queue of global requests that we expect replies on.
       (pending_global_requests struct object_queue)
       
       ; If non-zero, close connection after all active channels have
       ; died.
       (pending_close simple int)

       ; FIXME: Perhaps we should use an flag to indicate whether or
       ; not new channels can be opened?
       ))
*/

/* SSH_MSG_GLOBAL_REQUEST */

/* GABA:
   (class
     (name global_request_callback)
     (vars
       (response method int "int success")
       (connection object ssh_connection)))
*/

#define GLOBAL_REQUEST_CALLBACK(c, s) \
((c) ? ((c)->response((c), (s))) : LSH_OK | LSH_GOON)

/* GABA:
   (class
     (name global_request)
     (vars
       (handler method int "struct ssh_connection *connection"
                           "struct simple_buffer *args"
			   "struct global_request_callback *response")))
*/

#define GLOBAL_REQUEST(r, c, a, n) ((r)->handler((r), (c), (a), (n)))

/* SSH_MSG_CHANNEL_OPEN */
  
/* Callback function, used to report success or failure for a
 * requested channel open. */
  
/* GABA:
   (class
     (name channel_open_callback)
     (vars
       (response method int
                "struct ssh_channel *channel"
                "UINT32 error"
                "char *error_msg"
                "struct lsh_string *args")
       (connection object ssh_connection)))
*/

/* xxCLASS:
   (class
     (name channel_open_response)
     (vars
       (response method int
                "struct ssh_channel *channel"
                "UINT32 error"
		; FIXME: Use an lsh_string for error messages
                "char *error_msg"
                "struct lsh_string *args")
       (connection object ssh_connection)
       (remote_channel_number simple UINT32)
       (window_size simple UINT32)
       (max_packet simple UINT32)))
*/

#define CHANNEL_OPEN_CALLBACK(c, ch, e, m, a) \
  (c)->response((c), (ch), (e), (m), (a))

/* GABA:
   (class
     (name channel_open)
     (vars
       (handler method int
                "struct ssh_connection *connection"
                "struct simple_buffer *data"
                "struct channel_open_callback *response")))
*/

#define CHANNEL_OPEN(o, c, d, n) \
((o)->handler((o), (c), (d), (n)))

/* SSH_MSG_CHANNEL_REQUEST */
/* GABA:
   (class
     (name channel_request)
     (vars
       (handler method int
		"struct ssh_channel *channel"
		"struct ssh_connection *connection"
		"int want_reply"
		"struct simple_buffer *args")))
*/

#define CHANNEL_REQUEST(s, c, conn, w, a) \
((s)->handler((s), (c), (conn), (w), (a)))

/* ;;GABA:
   (class
     (name connection_startup)
     (vars
       (start method int
	      "struct ssh_connection *connection")))
*/

/* #define CONNECTION_START(c, s) ((c)->start((c), (s))) */

void init_channel(struct ssh_channel *channel);

struct channel_table *make_channel_table(void);
int alloc_channel(struct channel_table *table);
void dealloc_channel(struct channel_table *table, int i);
int register_channel(struct channel_table *table, struct ssh_channel *channel);
struct ssh_channel *lookup_channel(struct channel_table *table, UINT32 i);

struct abstract_write *make_channel_write(struct ssh_channel *channel);
struct abstract_write *make_channel_write_extended(struct ssh_channel *channel,
						   UINT32 type);

struct read_handler *make_channel_read_data(struct ssh_channel *channel);
struct read_handler *make_channel_read_stderr(struct ssh_channel *channel);

struct lsh_string *format_global_failure(void);
struct lsh_string *format_global_success(void);

struct lsh_string *format_open_failure(UINT32 channel, UINT32 reason,
				       const char *msg, const char *language);
struct lsh_string *format_open_confirmation(struct ssh_channel *channel,
					    UINT32 channel_number,
					    const char *format, ...);

struct lsh_string *format_channel_success(UINT32 channel);
struct lsh_string *format_channel_failure(UINT32 channel);

struct lsh_string *prepare_window_adjust(struct ssh_channel *channel,
					 UINT32 add);

struct lsh_string *prepare_channel_open(struct channel_table *table,
					int type,
					struct ssh_channel *channel,
					const char *format, ...);

struct lsh_string *format_channel_request(int type,
					  struct ssh_channel *channel,
					  int want_reply,
					  const char *format, ...);

struct lsh_string *format_channel_close(struct ssh_channel *channel);
struct lsh_string *format_channel_eof(struct ssh_channel *channel);

int channel_close(struct ssh_channel *channel);
int channel_eof(struct ssh_channel *channel);

struct close_callback *make_channel_close(struct ssh_channel *channel);

struct lsh_string *channel_transmit_data(struct ssh_channel *channel,
					 struct lsh_string *data);

struct lsh_string *channel_transmit_extended(struct ssh_channel *channel,
					     UINT32 type,
					     struct lsh_string *data);

struct command *make_connection_service(struct alist *global_requests,
					struct alist *channel_types);


#endif /* LSH_CHANNEL_H_INCLUDED */
