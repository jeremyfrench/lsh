/* encrypt.c
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

#include "encrypt.h"

#include "format.h"
#include "xalloc.h"

struct packet_encrypt
{
  struct abstract_write_pipe super;
  UINT32 sequence_number;

  struct ssh_connection *connection;
};

static int do_encrypt(struct abstract_write *w,
		      struct lsh_string *packet)
{
  struct packet_encrypt *closure = (struct packet_encrypt *) w;
  struct ssh_connection *connection = closure->connection;
  struct lsh_string *new;
  UINT8 *mac;

  MDEBUG(closure);
  
  new = ssh_format("%lr%lr", packet->length, NULL,
		   connection->send_mac ? connection->send_mac->mac_size : 0,
		   &mac);

  if (connection->send_crypto)
    CRYPT(connection->send_crypto, packet->length, packet->data, new->data);
  else
    memcpy(new->data, packet->data, packet->length);
  
  if (connection->send_mac)
  {
    UINT8 s[4];
    WRITE_UINT32(s, closure->sequence_number);

    closure->sequence_number++;
    
    HASH_UPDATE(connection->send_mac, 4, s);
    HASH_UPDATE(connection->send_mac, packet->length, packet->data);
    HASH_DIGEST(connection->send_mac, mac);
  }
  lsh_string_free(packet);

  return A_WRITE(closure->super.next, new);
}

struct abstract_write *
make_packet_encrypt(struct abstract_write *continuation,
		    struct ssh_connection *connection)
{
  struct packet_encrypt *closure;

  NEW(closure);

  closure->super.super.write = do_encrypt;
  closure->super.next = continuation;
  closure->sequence_number = 0;
  closure->connection = connection;

  return &closure->super.super;
}

    
