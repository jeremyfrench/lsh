/* connection_commands.h
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
#ifndef LSH_CONNECTION_COMMANDS_H_INCLUDED
#define LSH_CONNECTION_COMMANDS_H_INCLUDED

#include "alist.h"
#include "command.h"
#include "connection.h"
#include "keyexchange.h"
#include "ssh1_fallback.h"

#define GABA_DECLARE
#include "connection_commands.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name handshake_info)
     (vars
       ; Initial value for the connection flags. Usually
       ; CONNECTION_SERVER or CONNECTION_CLIENT
       (flags . UINT32)
       
       (block_size simple UINT32)
       (id_comment simple "const char *")
       (debug_comment simple "const char *")

       (random object randomness)
       (algorithms object alist)
       
       (init object make_kexinit)
       
       ;; Used only on the server
       (fallback object ssh1_fallback)))
*/

struct handshake_info *
make_handshake_info(UINT32 flags,
		    const char *id_comment,
		    const char *debug_comment,
		    UINT32 block_size,
		    struct randomness *r,
		    struct alist *algorithms,
		    struct make_kexinit *init,
		    struct ssh1_fallback *fallback);

extern struct collect_info_1 handshake_command;
#define CONNECTION_HANDSHAKE (&handshake_command.super.super.super)

struct close_callback *make_connection_close_handler(struct ssh_connection *c);

extern struct command_simple connection_remember;
#define CONNECTION_REMEMBER (&connection_remember.super.super)

struct command *
make_connection_if_srp(struct command *then_f,
		       struct command *else_f);

extern struct collect_info_1 connection_if_srp_command;
#define CONNECTION_IF_SRP (&connection_if_srp_command.super.super.super)

extern struct command connection_require_userauth;
#define CONNECTION_REQUIRE_USERAUTH (&connection_require_userauth.super)

#endif /* LSH_CONNECTION_COMMANDS_H_INCLUDED */
