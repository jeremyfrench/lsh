/* channel_commands.h
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

#include "channel.h"

#define GABA_DECLARE
#include "channel_commands.h.x"
#undef GABA_DECLARE

/* Command to open a new channel. Takes a connection as argument
 * returns a new channel or NULL if opening failed. */

/* GABA:
   (class
     (name channel_open_command)
     (super command)
     (vars
       ;; This method should return a partially filled in channel,
       ;; and create a channel open request by calling
       ;; prepare_channel_open.
       (new_channel method "struct ssh_channel *"
                    "struct ssh_connection *connection"
                    "struct lsh_string **request")))
*/

#define NEW_CHANNEL(s, c,r) ((s)->new_channel((s), (c), (r)))

int do_channel_open_command(struct command *s,
			    struct lsh_object *x,
			    struct command_continuation *c);

/* Takes a channel as argument, and returns the same channel or NULL. */
/* GABA:
   (class
     (name channel_request_command)
     (super command)
     (vars
       ;; This method should return a formatted request. The
       ;; want_reply field in the request should be non_zero iff *c is
       ;; non-NULL on return.  
       (format_request method "struct lsh_string *"
                       "struct ssh_channel *channel"
		       "struct command_continuation **c")))
*/

#define FORMAT_CHANNEL_REQUEST(r, c, w) \
((r)->format_request((r), (c), (w)))

int do_channel_request_command(struct command *s,
			       struct lsh_object *x,
			       struct command_continuation *c);
     
