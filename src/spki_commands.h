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

#include "command.h"
#include "spki.h"

struct command *
make_spki_read_acls(struct alist *algorithms);

extern struct command_simple spki_make_context_command;
#define SPKI_MAKE_CONTEXT (&spki_make_context_command.super.super)

extern struct command_simple spki_read_acls_command;
#define SPKI_READ_ACLS (&spki_read_acls_command.super.super.super)

extern struct command_simple spki_read_hostkeys_command;
#define SPKI_READ_HOSTKEYS (&spki_read_hostkeys_command.super.super)

extern struct command_simple spki_read_userkeys_command;
#define SPKI_READ_USERKEYS (&spki_read_userkeys_command.super.super)

struct command *
make_spki_read_userkeys(struct alist *algorithms);

/* Encryption of private data. */
struct command *
make_pkcs5_encrypt(struct randomness *r,
		   struct lsh_string *label,
		   UINT32 prf_name,
		   struct mac_algorithm *prf,
		   UINT32 crypto_name,
		   struct crypto_algorithm *crypto,
		   UINT32 salt_length,
		   struct lsh_string *password,
		   UINT32 iterations);

#endif /* LSH_SPKI_COMMANDS_H_INCLUDED */
