/* spki_commands.h
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Niels Möller
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

#ifndef LSH_SPKI_COMMANDS_H_INCLUDED
#define LSH_SPKI_COMMANDS_H_INCLUDED

#warning spki_commands.h is obsolete
#include "command.h"
#include "interact.h"
#include "spki.h"


extern struct command_2 spki_sexp2keypair_command;
#define SEXP2KEYPAIR (&spki_sexp2keypair_command.super.super)

extern struct command spki_make_context_command;
#define SPKI_MAKE_CONTEXT (&spki_make_context_command.super)

extern struct command spki_read_hostkeys_command;
#define SPKI_READ_HOSTKEYS (&spki_read_hostkeys_command.super)

struct command *
make_spki_read_userkeys(struct alist *algorithms,
			struct alist *signature_algorithms,
			struct interact *tty);
			

/* Encryption of private data. */

struct command *
make_pkcs5_decrypt(struct alist *mac_algorithms,
		   struct alist *crypto_algorithms,
		   struct interact *tty);

#endif /* LSH_SPKI_COMMANDS_H_INCLUDED */
