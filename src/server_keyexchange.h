/* server_keyexchange.h
 *
 * Server specific key exchange handling
 *
 * $Id$ */

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

#ifndef LSH_SERVER_KEYEXCHANGE_H_INCLUDED
#define LSH_SERVER_KEYEXCHANGE_H_INCLUDED

#include "keyexchange.h"
#include "publickey_crypto.h"

/* This function consumes the server key */
struct keyexchange_algorithm *
make_dh_server(struct diffie_hellman_method *dh);
     /* struct alist *keys); */

struct install_keys *make_server_install_keys(struct object_list *algorithms);

#endif /* LSH_SERVER_KEYEXCHANGE_H_INCLUDED */
