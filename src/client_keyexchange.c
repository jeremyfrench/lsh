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
  struct hash_instance *hash;;
  struct lsh_string *s;
  
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
    
  /* Key exchange successful! Send a newkeys message, and install a
   * handler for recieving the newkeys message. */

  /* Record session id */
  if (!connection->session_id)
    connection->session_id = closure->dh.exchange_hash;
  
  /* A hash instance initialized with the key, to be used for key generation */
  
  hash = MAKE_HASH(closure->dh->method->hash);
  s = ssh_format("%n", closure->dh->K);
  HASH_UPDATE(hash, s->length, s->data);
  lsh_string_free(s);

  res = prepare_keys(connection, hash);
  lsh_free(hash);

  return res;
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

  dh->verifier = closure->verifier;

  /* Send client's message */
  A_WRITE(connection->write, dh_make_client_msg(&dh->dh));

  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = &dh->super;

  /* Disable kexinit handler */
  dh->saved_kexinit_handler = connection->dispatch[SSH_MSG_KEXINIT];
  connection->dispatch[SSH_MSG_KEXINIT] = connection->fail;

  return WRITE_OK;
}

int prepare_keys_client(struct hash_instance *secret,
			struct ssh_connection *connection)
{
  /* FIXME: For DES, instantiating a crypto may fail, if the key
   * happens to be weak. */
  /* FIXME: No IV:s */

  struct crypto_instance *crypt_client_to_server
    = kex_make_encrypt(secret, KEX_ENCRYPTION_CLIENT_TO_SERVER, connection);
  struct crypto_instance *crypt_server_to_client
    = kex_make_decrypt(secret, KEX_ENCRYPTION_SERVER_TO_CLIENT, connection);
  
  struct mac_instance *mac_client_to_server
    = kex_make_mac(secret, KEX_MAC_CLIENT_TO_SERVER, connection);
  struct mac_instance *mac_server_to_client
    = kex_make_mac(secret, KEX_MAC_SERVER_TO_CLIENT, connection);

  
  
