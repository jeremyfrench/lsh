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
#include "werror.h"

#define GABA_DECLARE
#include "client.h.x"
#undef GABA_DECLARE

/* The argp option group for actions. */
#define CLIENT_ARGP_ACTION_GROUP 100
#define CLIENT_ARGP_MODIFIER_GROUP 200

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
struct abstract_write *
make_handle_escape(struct escape_info *info, struct abstract_write *next);

struct channel_request *make_handle_exit_status(int *exit_code);
struct channel_request *make_handle_exit_signal(int *exit_code);

struct command *make_open_session_command(struct ssh_channel *session);


extern struct command request_shell;
#define REQUEST_SHELL (&request_shell.super)

struct command *
make_session_channel_request(int type, struct lsh_string *arg);

extern struct command client_start_io;
#define CLIENT_START_IO (&client_start_io.super)

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

       ; The pty-allocation code adds resources here.
       (resources object resource_list)

       ; Commands to be invoked after the session is opened.
       (requests struct object_queue)

       ; For errors when opening the channel, or when sending the
       ; channel requests. It's not clear what's the proper place for
       ; the error handling.
       (e object exception_handler)

       ; Escape char handling
       (escape object escape_info)
       ; Where to save the exit code.
       (exit_status . "int *")))
*/

struct client_session *
make_client_session_channel(int in, int out, int err,
			    struct exception_handler *e,
			    struct escape_info *escape,
			    uint32_t initial_window,
			    int *exit_status);

struct command *
make_exec_request(struct lsh_string *command);

struct command *
make_pty_request(struct interact *tty);

struct command *
make_subsystem_request(struct lsh_string *subsystem);

extern struct channel_open channel_open_x11;

struct command *
make_forward_x11(const char *display_string,
		 struct randomness *random);

struct client_x11_display *
make_client_x11_display(const char *display, struct lsh_string *fake);

/* GABA:
   (class
     (name client_options)
     (super werror_config)
     (vars
       ;; Used only by lsh, NULL for lshg.
       (random object randomness)

       (tty object interact)

       ; -1 means default.
       (escape . int)
       
       (handler object exception_handler)

       (exit_code . "int *")

       (not . int)
       (port . "const char *")
       (target . "const char *")

       (local_user . "char *")
       (user . "char *")

       (with_remote_peers . int)
       
       ; -1 means default behaviour
       (with_pty . int)

       (with_x11 . int)
       
       ; Session modifiers
       (stdin_file . "const char *")
       (stdout_file . "const char *")
       (stderr_file . "const char *")

       ; True if the process's stdin or pty (respectively) has been used. 
       (used_stdin . int)
       (used_pty . int)
       (used_x11 . int)

       ; Should -B write the pid to stdout?
       (write_pid . int)
       
       ; True if the client should detach when a session closes (useful for gateways)
       (detach_end . int)

       ; Inhibit actions, used to not create actions from environment parsing.
       (inhibit_actions . int)

       (start_shell . int)
       (remote_forward . int)
       (actions struct object_queue)

       ; Resources that are created during argument parsing. These should be adopted
       ; by the connection once it is up and running.
       (resources object resource_list)))
*/

void
init_client_options(struct client_options *options,
		    struct randomness *random,
		    struct exception_handler *handler,
		    int *exit_code);

struct command *
client_add_action(struct client_options *options,
		  struct command *action);
struct command *
client_prepend_action(struct client_options *options,
		      struct command *action);

int
client_parse_forward_arg(char *arg,
			 unsigned long *listen_port,
			 struct address_info **target);

extern const struct argp client_argp;


void
env_parse(const struct argp *argp,
	  const char *value,
	  unsigned flags,
	  void *input);

#endif /* LSH_CLIENT_H_INCLUDED */
