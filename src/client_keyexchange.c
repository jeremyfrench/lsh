/* client_keyexchange.c
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

#include "client_keyexchange.h"

static void do_handle_dh_reply(struct packet_handler *c,
			       struct ssh_connection *connection,
			       struct lsh_string *packet);
{
  struct dh_client *closure = (struct dh_client *) c;
  struct verifier *v;
  
  if (!dh_process_server_msg(&closure->dh, packet))
    return send_disconnect(connection, "Bad dh-reply\r\n");

  v = LOOKUP_VERIFIER(closure->verifier, closure->dh.server_host_key);

  if (!v)
    /* FIXME: Use a more appropriate error code. Should probably have
     * a separate file for sending and recieving various types of
     * disconnects. */
    return send_disconnect(connection, "Bad server host key\r\n");

  if (!dh_verify_server_msg(&closure->dh, v))
    /* FIXME: Same here */
    return send_disconnect(connection, "Bad server host key\r\n");
    
  /* Key exchange successful! */
  
  
  
}

static void do_init_dh(struct keyexchange_algorithm *c,
		       struct ssh_connection *connection)
{
  struct dh_algorithm_client *closure = (struct dh_algorithm_client *) c;
  struct dh_client *dh = xalloc(sizeof(struct dh_client));
  struct lsh_string *msg;

  /* Initialize */
  dh->super.handler = do_handle_dh_reply;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->hash = MAKE_HASH(closure->hash);
  dh->signature_algorithm = closure->signature_algorithm;

  /* Send client's message */
  A_WRITE(connection->write, dh_make_client_msg(&dh->dh));

  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = &dh->super;

  /* Disable kexinit handler */
  dh->saved_kexinit_handler = connection->dispatch[SSH_MSG_KEXINIT];
  connection->dispatch[SSH_MSG_KEXINIT] = connection->fail;

  return WRITE_OK;
}

