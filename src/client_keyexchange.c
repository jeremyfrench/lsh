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

#include "atoms.h"
#include "debug.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

struct dh_client_exchange
{
  struct keyexchange_algorithm super;
  struct diffie_hellman_method *dh;
  struct lookup_verifier *verifier;
};

/* Handler for the kex_dh_reply message */
struct dh_client
{
  struct packet_handler super;
  struct diffie_hellman_instance dh;
  struct lookup_verifier *verifier;
  struct install_keys *install;
};

static int do_handle_dh_reply(struct packet_handler *c,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  struct dh_client *closure = (struct dh_client *) c;
  struct verifier *v;
  struct hash_instance *hash;
  struct lsh_string *s;
  int res;

  MDEBUG(closure);
  
  verbose("handle_dh_reply()\n");
  
  if (!dh_process_server_msg(&closure->dh, packet))
    {
      disconnect_kex_failed(connection, "Bad dh-reply\r\n");
      return LSH_FAIL | LSH_CLOSE;
    }
    
  v = LOOKUP_VERIFIER(closure->verifier, closure->dh.server_key);

  if (!v)
    /* FIXME: Use a more appropriate error code? */
    {
      disconnect_kex_failed(connection, "Bad server host key\r\n");
      return LSH_FAIL | LSH_CLOSE;
    }
  
  if (!dh_verify_server_msg(&closure->dh, v))
    /* FIXME: Same here */
    return disconnect_kex_failed(connection, "Invalid server signature\r\n");
    
  /* Key exchange successful! Send a newkeys message, and install a
   * handler for recieving the newkeys message. */

  res = A_WRITE(connection->write, ssh_format("%c", SSH_MSG_NEWKEYS));
  if (LSH_PROBLEMP(res))
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

  connection->dispatch[SSH_MSG_KEXDH_REPLY] = connection->fail;
  connection->kex_state = KEX_STATE_NEWKEYS;
  
  return send_verbose(connection->write, "Key exchange successful!", 0);
}

static int do_init_dh(struct keyexchange_algorithm *c,
		      struct ssh_connection *connection,
		      int hostkey_algorithm_atom,
		      struct signature_algorithm *ignored,
		      void **algorithms)
{
  struct dh_client_exchange *closure = (struct dh_client_exchange *) c;
  struct dh_client *dh = xalloc(sizeof(struct dh_client));

  int res;

  MDEBUG(c);
  MDEBUG(connection);
  MDEBUG(ignored);
  
  /* FIXME: Use this value to choose a verifier function */
  if (hostkey_algorithm_atom != ATOM_SSH_DSS)
    fatal("Internal error\n");
  
  /* Initialize */
  dh->super.handler = do_handle_dh_reply;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->verifier = closure->verifier;

  dh->install = make_client_install_keys(algorithms);
  
  /* Send client's message */
  res = A_WRITE(connection->write, dh_make_client_msg(&dh->dh));

  if (LSH_PROBLEMP(res))
    return res;
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = &dh->super;
  
  connection->kex_state = KEX_STATE_IN_PROGRESS;
  
  return LSH_OK | LSH_GOON;
}


/* FIXME: This assumes that there's only one hostkey-algorithm. To
 * fix, this constructor should take a mapping
 * algorithm->verifier-function. The init-method should use this
 * mapping to find an appropriate verifier function. */

struct keyexchange_algorithm *
make_dh_client(struct diffie_hellman_method *dh,
	       struct lookup_verifier *verifier)
{
  struct dh_client_exchange *self = xalloc(sizeof(struct dh_client_exchange));

  MDEBUG(dh);
  
  self->super.init = do_init_dh;
  self->dh = dh;
  self->verifier = verifier;

  return &self->super;
}

struct client_install_keys
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

  struct client_install_keys *closure = (struct client_install_keys *) c;

  MDEBUG(closure);

  /* Keys for recieving */
  connection->dispatch[SSH_MSG_NEWKEYS] = make_newkeys_handler
    (kex_make_encrypt(secret, closure->algorithms,
		      KEX_ENCRYPTION_SERVER_TO_CLIENT, connection),
     kex_make_mac(secret, closure->algorithms,
		  KEX_MAC_SERVER_TO_CLIENT, connection));

  /* Keys for sending */
  /* NOTE: The NEWKEYS-message should have been sent before this
   * function is called */
  connection->send_crypto 
    = kex_make_decrypt(secret, closure->algorithms,
		       KEX_ENCRYPTION_CLIENT_TO_SERVER, connection);
  
  connection->send_mac 
    = kex_make_mac(secret, closure->algorithms,
		   KEX_MAC_CLIENT_TO_SERVER, connection);

  return 1;
}

struct install_keys *make_client_install_keys(void **algorithms)
{
  struct client_install_keys *self = xalloc(sizeof(struct client_install_keys));

  self->super.install = do_install;
  self->algorithms = algorithms;

  return &self->super;
}
