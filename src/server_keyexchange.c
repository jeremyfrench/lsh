/* server_keyexchange.c
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

#include "server_keyexchange.h"

#include "atoms.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

struct install_keys *make_server_install_keys(void **algorithms);

static int do_handle_dh_init(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct dh_server *closure = (struct dh_server *) c;
  struct hash_instance *hash;
  struct lsh_string *s;
  int res;

  MDEBUG(closure);
  
  verbose("handle_dh_init()\n");
  
  if (!dh_process_client_msg(&closure->dh, packet))
    {
      disconnect_kex_failed(connection, "Bad dh-init\r\n");
      return WRITE_CLOSED;
    }
  
  /* Send server's message, to complete key exchange */
  res = A_WRITE(connection->write, dh_make_server_msg(&closure->dh,
						      closure->signer));

  if (res != WRITE_OK)
    return res;
  
  /* Send a newkeys message, and install a handler for recieving the
   * newkeys message. */

  res = A_WRITE(connection->write, ssh_format("%c", SSH_MSG_NEWKEYS));
  if (res != WRITE_OK)
    return res;

  /* Record session id */
  if (!connection->session_id)
    {
      connection->session_id = closure->dh.exchange_hash;
      closure->dh.exchange_hash = NULL; /* For gc */
    }
  
  /* A hash instance initialized with the key, to be used for key generation */
  
  hash = MAKE_HASH(closure->dh.method->H);
  s = ssh_format("%n", closure->dh.K);
  HASH_UPDATE(hash, s->length, s->data);
  lsh_string_free(s);
  
  res = INSTALL_KEYS(closure->install, connection, hash);

  lsh_free(hash);

  connection->kex_state = KEX_STATE_NEWKEYS;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;
  
  return res;
}

static int do_init_dh(struct keyexchange_algorithm *c,
		      struct ssh_connection *connection,
		      int hostkey_algorithm_atom,
		      struct signature_algorithm *ignored,
		      void **algorithms)
{
  struct dh_server_exchange *closure = (struct dh_server_exchange *) c;
  struct dh_server *dh = xalloc(sizeof(struct dh_server));

  MDEBUG(closure);
  
  /* FIXME: Use this value to choose a signer function */
  if (hostkey_algorithm_atom != ATOM_SSH_DSS)
    fatal("Internal error\n");
  
  /* Initialize */
  dh->super.handler = do_handle_dh_init;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->dh.server_key = closure->server_key;
  dh->signer = closure->signer;

  dh->install = make_server_install_keys(algorithms);

  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_INIT] = &dh->super;

  connection->kex_state = KEX_STATE_IN_PROGRESS;

  return WRITE_OK;
}


/* FIXME: This assumes that there's only one hostkey-algorithm. To
 * fix, this constructor should take a mapping
 * algorithm->signer-function. The init-method should use this
 * mapping to find an appropriate signer function. */

struct keyexchange_algorithm *
make_dh_server(struct diffie_hellman_method *dh,
	       struct lsh_string *server_key,
	       struct signer *signer)
{
  struct dh_server_exchange *self = xalloc(sizeof(struct dh_server_exchange));

  self->super.init = do_init_dh;
  self->dh = dh;
  self->server_key = server_key;
  self->signer = signer;

  return &self->super;
}

struct server_install_keys
{
  struct install_keys super;
  void **algorithms;
};

static int do_install(struct install_keys *c,
		      struct ssh_connection *connection,
		      struct hash_instance *secret)
{
  /* FIXME: For DES, instantiating a crypto may fail, if the key
   * happens to be weak. */
  /* FIXME: No IV:s */

  struct server_install_keys *closure = (struct server_install_keys *) c;
  
  MDEBUG(closure);

  /* Keys for recieving */
  connection->dispatch[SSH_MSG_NEWKEYS] = make_newkeys_handler
    (kex_make_encrypt(secret, closure->algorithms,
		      KEX_ENCRYPTION_CLIENT_TO_SERVER, connection),
     kex_make_mac(secret, closure->algorithms,
		  KEX_MAC_CLIENT_TO_SERVER, connection));

  /* Keys for sending */
  /* NOTE: The NEWKEYS-message should have been sent before this
   * function is called */
  connection->send_crypto 
    = kex_make_decrypt(secret, closure->algorithms,
		       KEX_ENCRYPTION_SERVER_TO_CLIENT, connection);
  
  connection->send_mac 
    = kex_make_mac(secret, closure->algorithms,
		   KEX_MAC_SERVER_TO_CLIENT, connection);

  return 1;
}

struct install_keys *make_server_install_keys(void **algorithms)
{
  struct server_install_keys *self = xalloc(sizeof(struct server_install_keys));

  self->super.install = do_install;
  self->algorithms = algorithms;

  return &self->super;
}
