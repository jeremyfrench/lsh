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

#define CLASS_DEFINE
#include "client_keyexchange.h.x"
#undef CLASS_DEFINE

#include "client_keyexchange.c.x"

/* CLASS:
   (class
     (name dh_client_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object diffie_hellman_method)
       (verifier object lookup_verifier)))
*/

#if 0     
struct dh_client_exchange
{
  struct keyexchange_algorithm super;
  struct diffie_hellman_method *dh;
  struct lookup_verifier *verifier;
};
#endif

/* Handler for the kex_dh_reply message */
/* CLASS:
   (class
     (name dh_client)
     (super packet_handler)
     (vars
       (dh struct diffie_hellman_instance)
       (verifier object lookup_verifier)
       (install object install_keys)
       (finished object ssh_service)))
*/

#if 0
struct dh_client
{
  struct packet_handler super;
  struct diffie_hellman_instance dh;
  struct lookup_verifier *verifier;
  struct install_keys *install;
  
  struct ssh_service *finished;
};
#endif
    
static int do_handle_dh_reply(struct packet_handler *c,
			      struct ssh_connection *connection,
			      struct lsh_string *packet)
{
  CAST(dh_client, closure, c);
  struct verifier *v;
  struct hash_instance *hash;
  struct lsh_string *s;
  int res;

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
  if (LSH_CLOSEDP(res))
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
  
  /* FIXME: Return value is ignored */
  (void) INSTALL_KEYS(closure->install, connection, hash);

  KILL(hash);

  connection->dispatch[SSH_MSG_KEXDH_REPLY] = connection->fail;
  connection->kex_state = KEX_STATE_NEWKEYS;
  
  res |= send_verbose(connection->write, "Key exchange successful!", 0);
  if (LSH_CLOSEDP(res))
    return res;
  
  return res | SERVICE_INIT(closure->finished, connection);
}

static int do_init_dh(struct keyexchange_algorithm *c,
		      struct ssh_connection *connection,
		      struct ssh_service *finished,
		      int hostkey_algorithm_atom,
		      struct signature_algorithm *ignored,
		      struct object_list *algorithms)
{
  CAST(dh_client_exchange, closure, c);
  NEW(dh_client, dh);

  int res;

  CHECK_SUBTYPE(ssh_connection, connection);
  CHECK_SUBTYPE(signature_algorithm, ignored);

  /* FIXME: Use this value to choose a verifier function */
  if (hostkey_algorithm_atom != ATOM_SSH_DSS)
    fatal("Internal error\n");
  
  /* Initialize */
  dh->super.handler = do_handle_dh_reply;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->verifier = closure->verifier;
  dh->install = make_client_install_keys(algorithms);
  dh->finished = finished;
  
  /* Send client's message */
  res = A_WRITE(connection->write, dh_make_client_msg(&dh->dh));

  if (LSH_CLOSEDP(res))
    return res | LSH_FAIL;
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = &dh->super;
  
  connection->kex_state = KEX_STATE_IN_PROGRESS;
  
  return res | LSH_OK | LSH_GOON;
}


/* FIXME: This assumes that there's only one hostkey-algorithm. To
 * fix, this constructor should take a mapping
 * algorithm->verifier-function. The init-method should use this
 * mapping to find an appropriate verifier function. */

struct keyexchange_algorithm *
make_dh_client(struct diffie_hellman_method *dh,
	       struct lookup_verifier *verifier)
{
  NEW(dh_client_exchange, self);

  CHECK_TYPE(diffie_hellman_method, dh);
  
  self->super.init = do_init_dh;
  self->dh = dh;
  self->verifier = verifier;

  return &self->super;
}

/* FIXME: This is identical to the server_install_keys structure in
 * server_keyexchange.c. It should probably be moved somewhere else. */

/* CLASS:
   (class
     (name client_install_keys)
     (super install_keys)
     (vars
       (algorithms object object_list)))
*/

#if 0
struct client_install_keys
{
  struct install_keys super;
  struct object_list *algorithms;
};
#endif

static int do_install(struct install_keys *c,
		      struct ssh_connection *connection,
		      struct hash_instance *secret)
{
  /* FIXME: For DES, instantiating a crypto may fail, if the key
   * happens to be weak. */
  /* FIXME: No IV:s */

  CAST(client_install_keys, closure, c);

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

struct install_keys *make_client_install_keys(struct object_list *algorithms)
{
  NEW(client_install_keys, self);

  self->super.install = do_install;
  self->algorithms = algorithms;

  return &self->super;
}
