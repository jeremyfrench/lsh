/* channel.h
 *
 * Information about ssh channels.
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

#ifndef LSH_CHANNEL_H_INCLUDED
#define LSH_CHANNEL_H_INCLUDED

#include "alist.h"
#include "command.h"
#include "connection.h"
#include "parse.h"
#include "server_pty.h"
#include "write_buffer.h"

enum channel_event
{
  /* We receieved a CHANNEL_OPEN_CONFIRMATION. */
  CHANNEL_EVENT_CONFIRM = 1,
#if 0
  /* We received a CHANNEL_OPEN_FAILURE. */
  CHANNEL_EVENT_DENY,
#endif
  /* We received a CHANNEL_EOF or CHANNEL_CLOSE. */
  CHANNEL_EVENT_EOF,
  /* Local buffers are full. Stop sending data. */
  CHANNEL_EVENT_STOP,
  /* Start sending again (subject to the current send window size). */
  CHANNEL_EVENT_START,
};

struct channel_request_info
{
  uint32_t type_length;
  const uint8_t *type_data;
  
  int type;

  int want_reply;
};

#define GABA_DECLARE
#include "channel.h.x"
#undef GABA_DECLARE

/* Channels are indexed by local channel number in some array. When
   sending messages on the channel, it is identified by the *remote*
   side's index number, and this number must be stored. */

enum channel_data_type {
  CHANNEL_DATA = 0,
  CHANNEL_STDERR_DATA = 1,
};

enum channel_flag {
  CHANNEL_SENT_CLOSE = 1,
  CHANNEL_RECEIVED_CLOSE = 2,
  CHANNEL_SENT_EOF = 4,
  CHANNEL_RECEIVED_EOF = 8,

  /* This flags means that we don't expect any more data from the other
     end, and that we don't want to wait for an SSH_MSG_CHANNEL_EOF
     before closing the channel. */
  CHANNEL_NO_WAIT_FOR_EOF = 0x10
};

/* FIXME: Inherit resource */
/* GABA:
   (class
     (name ssh_channel)
     (super resource)
     (vars
       ; Remote channel number 
       (local_channel_number . uint32_t)
       (remote_channel_number . uint32_t)
       
       ; NOTE: The channel's maximum packet sizes refer to the packet
       ; payload, i.e. the DATA string in SSH_CHANNEL_DATA and
       ; SSH_MSG_CHANNEL_EXTENDED_DATA.

       (rec_window_size . uint32_t)
       (rec_max_packet . uint32_t)

       (send_window_size . uint32_t)
       (send_max_packet . uint32_t)

       (connection object ssh_connection)
       
       (request_types object alist)

       ; If non-NULL, invoked for unknown channel requests.
       (request_fallback object channel_request)
       
       (flags . int)

       ; Number of sources connected to this channel. We should not
       ; send CHANNEL_EOF until we have got EOF on all sources (e.g.
       ; stdout and stderr)
       (sources . unsigned)

       ; Number of sinks connected to the channel. We should not send
       ; CHANNEL_CLOSE until we have received CHANNEL_EOF and all
       ; buffered data have been written to the sinks. NOTE: A pending
       ; exit-status/exit-signal message to be sent or received is
       ; also book-keeped as a sink.       
       (sinks . unsigned)
       
       ; Type is CHANNEL_DATA or CHANNEL_STDERR_DATA
       (receive method void "int type"
		"uint32_t length" "const uint8_t *data")

       ; Called when we are allowed to send more data on the channel.
       ; Implies that the send_window_size is non-zero. 
       (send_adjust method void "uint32_t increment")

       (event method void "enum channel_event")
  
       ; Pass on responce from CHANNEL_OPEN
       (channel_open_context object command_context)

       ; Queue of channel requests that we expect replies on
       (pending_requests struct object_queue)

       ; Channel requests that we have received, and should reply to
       ; in the right order
       (active_requests struct object_queue)))
       
*/

#define CHANNEL_RECEIVE(s, t, l, d) \
((s)->receive((s), (t), (l), (d)))

#define CHANNEL_SEND_ADJUST(s, i) ((s)->send_adjust((s), (i)))
     
#define CHANNEL_CLOSE(s) \
((s)->close((s)))

#define CHANNEL_EVENT(s, t) \
((s)->event((s), (t)))

#define CHANNEL_OPEN_CONFIRM(s) \
((s)->open_confirm((s)))

#define CHANNEL_OPEN_FAILURE(s) \
((s)->open_failure((s)))



/* SSH_MSG_CHANNEL_REQUEST */

/* GABA:
   (class
     (name channel_request)
     (vars
       (handler method void
		"struct ssh_channel *channel"
		"struct channel_request_info *info"
		"struct simple_buffer *args"
		"struct command_continuation *c"
		"struct exception_handler *e")))
*/

#define CHANNEL_REQUEST(s, c, i, a, n, e) \
((s)->handler((s), (c), (i), (a), (n), (e)))

#define DEFINE_CHANNEL_REQUEST(name)                            \
static void do_##name(struct channel_request *s,                \
		      struct ssh_channel *channel,              \
                      struct channel_request_info *info,        \
		      struct simple_buffer *args,               \
		      struct command_continuation *c,           \
		      struct exception_handler *e);             \
                                                                \
struct channel_request name =                                   \
{ STATIC_HEADER, do_##name };                                   \
                                                                \
static void do_##name

void
init_channel(struct ssh_channel *channel,
	     void (*kill)(struct resource *),
	     void (*event)(struct ssh_channel *, enum channel_event));

void
register_channel(struct ssh_connection *table,
		 uint32_t local_channel_number,
		 struct ssh_channel *channel,
		 int take_into_use);

/* FIXME: Make static? */
struct ssh_channel *
lookup_channel(struct ssh_connection *table, uint32_t i);
struct ssh_channel *
lookup_channel_reserved(struct ssh_connection *table, uint32_t i);

void
channel_adjust_rec_window(struct ssh_channel *channel, uint32_t written);

void
channel_start_receive(struct ssh_channel *channel,
		      uint32_t initial_window_size);

struct lsh_string *
format_channel_open_s(struct lsh_string *type,
		      uint32_t local_channel_number,
		      struct ssh_channel *channel,
		      struct lsh_string *args);

struct lsh_string *
format_channel_open(int type, uint32_t local_channel_number,
		    struct ssh_channel *channel,
		    const char *format, ...);

struct lsh_string *
format_channel_request_i(struct channel_request_info *info,
			 struct ssh_channel *channel,
			 uint32_t args_length, const uint8_t *args_data);

struct lsh_string *
format_channel_request(int type,
		       struct ssh_channel *channel,
		       int want_reply,
		       const char *format, ...);

struct lsh_string *
format_global_request(int type, int want_reply,
		      const char *format, ...);

struct lsh_string *format_channel_close(struct ssh_channel *channel);
struct lsh_string *format_channel_eof(struct ssh_channel *channel);

void
channel_eof(struct ssh_channel *channel);

void
channel_close(struct ssh_channel *channel);

void
channel_maybe_close(struct ssh_channel *channel);

struct lsh_callback *
make_channel_read_close_callback(struct ssh_channel *channel);

struct exception_handler *
make_channel_io_exception_handler(struct ssh_channel *channel,
				  const char *prefix,
				  int silent,
				  struct exception_handler *parent,
				  const char *context);

void
channel_transmit_data(struct ssh_channel *channel,
		      uint32_t length, const uint8_t *data);

void
channel_transmit_extended(struct ssh_channel *channel,
			  uint32_t type,
			  uint32_t length, const uint8_t *data);

int
channel_packet_handler(struct ssh_connection *table,
		       uint32_t length, const uint8_t *packet);

#endif /* LSH_CHANNEL_H_INCLUDED */
