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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "server_keyexchange.h"

#include "atoms.h"
#include "debug.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "server_keyexchange.c.x"

/* CLASS:
   (class
     (name dh_server_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object diffie_hellman_method)
       (keys object alist)))
*/

/* Handler for the kex_dh_reply message */
/* CLASS:
   (class
     (name dh_server)
     (super packet_handler)
     (vars
       (dh struct diffie_hellman_instance)
       ;; (server_key string)
       (signer object signer)
       (install object install_keys)
       (finished object ssh_service)))
*/

static int do_handle_dh_init(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  CAST(dh_server, closure, c);
  struct hash_instance *hash;
  struct lsh_string *s;
  int res;

  verbose("handle_dh_init()\n");
  
  if (!dh_process_client_msg(&closure->dh, packet))
    {
      disconnect_kex_failed(connection, "Bad dh-init\r\n");
      return LSH_FAIL | LSH_CLOSE;
    }
  
  /* Send server's message, to complete key exchange */
  res = A_WRITE(connection->write, dh_make_server_msg(&closure->dh,
						      closure->signer));

  if (LSH_CLOSEDP(res))
    return res;
  
  /* Send a newkeys message, and install a handler for receiving the
   * newkeys message. */

  res |= A_WRITE(connection->write, ssh_format("%c", SSH_MSG_NEWKEYS));
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

  if (!INSTALL_KEYS(closure->install, connection, hash))
    {
      werror("Installing new keys failed. Hanging up.\n");
      KILL(hash);
      /* FIXME: Send a disconnect message */
      return LSH_FAIL | LSH_DIE;
    }

  KILL(hash);

  connection->kex_state = KEX_STATE_NEWKEYS;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;

  res |= send_verbose(connection->write, "Key exchange successful!", 0);
  if (LSH_CLOSEDP(res))
    return res;
  
  return res | SERVICE_INIT(closure->finished, connection);
}

static int do_init_server_dh(struct keyexchange_algorithm *c,
		             struct ssh_connection *connection,
		             struct ssh_service *finished,
		             int hostkey_algorithm_atom,
		             struct signature_algorithm *ignored,
		             struct object_list *algorithms)
{
  CAST(dh_server_exchange, closure, c);
  CAST(keypair_info, keypair, ALIST_GET(closure->keys,
					hostkey_algorithm_atom));
  NEW(dh_server, dh);

  CHECK_TYPE(ssh_connection, connection);
  CHECK_SUBTYPE(ssh_service, finished);
  CHECK_SUBTYPE(signature_algorithm, ignored);
  
  
  if (!keypair)
    {
      werror("Keypair for for selected signature-algorithm not found!\n");
      return LSH_FAIL | LSH_CLOSE;
    }
  
  /* Initialize */
  dh->super.handler = do_handle_dh_init;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->dh.server_key = lsh_string_dup(keypair->public);
  dh->signer = keypair->private;
  dh->install = make_install_new_keys(1, algorithms);
  dh->finished = finished;
  
  /* Generate server's secret exponent */
  dh_make_server_secret(&dh->dh);
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_INIT] = &dh->super;

  connection->kex_state = KEX_STATE_IN_PROGRESS;

  return LSH_OK  | LSH_GOON;
}


struct keyexchange_algorithm *
make_dh_server(struct diffie_hellman_method *dh,
	       struct alist *keys)
{
  NEW(dh_server_exchange, self);

  self->super.init = do_init_server_dh;
  self->dh = dh;
  self->keys = keys;

  return &self->super;
}

