/* keyexchange.h
 *
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_KEYEXCHANGE_H_INCLUDED
#define LSH_KEYEXCHANGE_H_INCLUDED

#include "lsh_types.h"
#include "abstract_io.h"
#include "alist.h"

#define KEX_ENCRYPTION_CLIENT_TO_SERVER 0
#define KEX_ENCRYPTION_SERVER_TO_CLIENT 1
#define KEX_MAC_CLIENT_TO_SERVER 2
#define KEX_MAC_SERVER_TO_CLIENT 3
#define KEX_COMPRESSION_CLIENT_TO_SERVER 4
#define KEX_COMPRESSION_SERVER_TO_CLIENT 5

#define KEX_PARAMETERS 6

struct keyexchange_algorithm
{
  int (*init)(struct keyexchange_algorithm *closure,
	      struct ssh_connection *connection,
	      struct signature_algorithm *hostkey_algorithm,
	      void **algorithms);
};

#define KEYEXCHANGE_INIT(kex, connection, ) \
((kex)->init((kex), (connection)))

struct kexinit
{
  UINT8 cookie[16];
  /* Zero terminated list of atoms */
  int *kex_algorithms; 
  int *server_host_key_algorithms;
  int *parameters[KEX_PARAMETERS];
  int *languages_client_to_server;
  int *languages_server_to_client;
  int first_kex_packet_follows;
};

/* This function generates a new kexinit message.
 *
 * FIXME: It could be replaced with a function that does more: Send
 * the message, record it in the connection structure, and possibly
 * send a first guessed message. */

struct generate_kexinit
{
  struct kexinit * (*generate)(struct generate_kexinit *closure);
};

#define GENERATE_KEXINIT(g) ((g)->generate((g)))

struct handle_keyexinit
{
  struct packet_handler super;
  struct choose_kexinit *init;

  /* Maps names to algorithms. It's dangerous to lookup random atoms
   * in this table, as not all objects have the same type. This
   * mapping is used only on atoms that have appeared in *both* the
   * client's and the server's list of algorithms (of a certain type),
   * and therefore the remote side can't screw things up. */

  struct alist *algorithms;
};

struct newkeys_info
{
  struct crypto_algorithm *encryption_client_to_server;
  struct crypto_algorithm *encryption_server_to_client;
  struct mac_algorithm *mac_client_to_server;
  struct mac_algorithm *mac_server_to_client;
#if 0
  struct compression_algorithm *compression_client_to_server;
  struct compression_algorithm *compression_server_to_client;
#endif
};


struct packet_handler *make_kexinit_handler();
struct packet_handler *make_newkeys_handler();

struct lsh_string *format_kex(struct kexinit *kex);

#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
