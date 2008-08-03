/* client.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001 Niels Möller
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

#ifndef LSH_CLIENT_H_INCLUDED
#define LSH_CLIENT_H_INCLUDED

#include "io.h"
#include "keyexchange.h"
#include "channel.h"
#include "channel_io.h"
#include "tcpforward.h"
#include "werror.h"

struct client_session;

enum escape_state { ESCAPE_GOT_NONE = 0, ESCAPE_GOT_NEWLINE, ESCAPE_GOT_ESCAPE };

#define GABA_DECLARE
#include "client.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name client_connection)
     (super ssh_connection)
     (vars
       (transport . int)
       (reader object service_read_state)
       (writer object ssh_write_state)
       ; Means we have an active write call back.
       (write_active . int)
       ; Means the write buffer has been filled up, and
       ; channels are stopped.
       (write_blocked . int)

       ; Queue of SSH_LSH_RANDOM_REQUEST we expect replies on.
       (pending_random struct object_queue)
       
       ;; When there are multiple X11-forwardings (requested by gateway
       ;; clients), the protocol lacks identification of which request
       ;; belongs to which forwarding. We use the one most recently
       ;; requested.
       (x11_displays object resource_list)
              
       ; Keeps track of all gatewayed connections
       (gateway_connections object resource_list)))
*/

struct client_connection *
make_client_connection(int fd);

/* GABA:
   (class
     (name client_random_handler)
     (vars
       ; Exactly one must be non-NULL
       (gateway object gateway_connection)
       (reply method void "uint32_t length" "const uint8_t *data")))
*/

void
client_random_request(struct client_connection *connection,
		      uint32_t length,
		      struct client_random_handler *handler);

void
client_gateway_random_request(struct client_connection *connection,
			      uint32_t length, const uint8_t *packet,
			      struct gateway_connection *gateway);


/* GABA:
   (class
     (name escape_callback)
     (super lsh_callback)
     (vars
       (help . "const char *")))
*/

#define DEFINE_ESCAPE(name, help) \
static void do_##name(struct lsh_callback *self); \
struct escape_callback \
name = { { STATIC_HEADER, do_##name }, help }; \
static void do_##name(struct lsh_callback *self UNUSED)

/* GABA:
   (class
     (name escape_info)
     (vars
       (escape . uint8_t)
       ; Handlers, indexed by character.
       (dispatch array (object escape_callback) "0x100")))
*/

struct escape_info *make_escape_info(uint8_t escape);
struct escape_info *
make_client_escape(uint8_t escape);

enum escape_state
client_escape_process(const struct escape_info *info, enum escape_state state,
		      uint32_t length, const uint8_t *data,
		      uint32_t *copy, uint32_t *done);

/* GABA:
   (class
     (name client_connection_action)
     (vars
       (action method void "struct ssh_connection *connection")))
*/

struct client_connection_action *
make_open_session_action(struct ssh_channel *channel);

/* GABA:
   (class
     (name client_session_action)
     (vars
       ; If non-zero, wait for previous requests to complete.
       (serial . int)
       ; FIXME: Use const methods? 
       (start method void "struct client_session *session")
       (success method void "struct client_session *session")
       ; Returns 1 if we should continue despite the error.
       (failure method int "struct client_session *session")))
*/

extern struct client_session_action
client_request_shell;

struct client_session_action *
make_exec_action(struct lsh_string *command);

struct client_session_action *
make_subsystem_action(struct lsh_string *subsystem);

struct client_session_action client_request_pty;

struct client_session_action *
make_x11_action(const char *display_string, int single_connection);

/* GABA:
   (class
     (name client_x11_handler)
     (super resource)
     (vars
       (single_connection . int)
       (open method void "const struct channel_open_info *info"
		         "struct simple_buffer *args")))
*/
   
void
client_add_x11_handler(struct client_connection *connection,
		       struct client_x11_handler *handler);

extern struct channel_open
channel_open_x11;

/* GABA:
   (class
     (name client_tcpforward_handler)
     (super forwarded_port)
     (vars
       (active . int)
       (open method void "const struct channel_open_info *info"
		         "uint32_t peer_ip_length"
			 "const uint8_t *peer_ip"
			 "uint32_t peer_port")))
*/

/* Initiate and manage a session */
/* GABA:
   (class
     (name client_session)
     (super ssh_channel)
     (vars
       ; Session stdio. The fd:s should be distinct, for simplicity in
       ; the close logic.       
       (in struct channel_read_state)
       (out struct channel_write_state)
       (err struct channel_write_state)

       (pty object resource)
       (x11 object resource)

       ; Actions to be invoked after the session is opened.
       (actions object object_list)
       ; Next action to start
       (action_next . unsigned)
       ; The action that the next received success or failure
       ; message corresponds to.
       (action_done . unsigned)

       ; Escape char handling
       (escape const object escape_info)
       (escape_state . "enum escape_state")

       ; Where to save the exit code.
       (exit_status . "int *")))
*/

struct client_session *
make_client_session_channel(int in, int out, int err,
			    struct object_list *actions,
			    struct escape_info *escape,
			    uint32_t initial_window,
			    int *exit_status);

struct lsh_string *
client_rebuild_command_line(unsigned argc, char **argv);

void
env_parse(const struct argp *argp,
	  const char *value,
	  unsigned flags,
	  void *input);

#endif /* LSH_CLIENT_H_INCLUDED */
