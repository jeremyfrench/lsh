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
#include "command.h"
#include "debug.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#include "server_keyexchange.c.x"

/* GABA:
   (class
     (name dh_server_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object diffie_hellman_method)))
       ;; Remove this?
       ;; (keys object alist)))
*/

/* Handler for the kex_dh_reply message */
/* GABA:
   (class
     (name dh_server)
     (super packet_handler)
     (vars
       (dh struct diffie_hellman_instance)
       ;; (server_key string)
       (signer object signer)
       (install object install_keys)))
*/

static void
do_handle_dh_init(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(dh_server, closure, c);
  struct hash_instance *hash;

  trace("handle_dh_init()\n");
  
  if (!dh_process_client_msg(&closure->dh, packet))
    {
      disconnect_kex_failed(connection, "Bad dh-init\r\n");
      return;
    }
  
  /* Send server's message, to complete key exchange */
  C_WRITE(connection,
	  dh_make_server_msg(&closure->dh,
			     closure->signer));

  /* Send a newkeys message, and install a handler for receiving the
   * newkeys message. */

  C_WRITE(connection, ssh_format("%c", SSH_MSG_NEWKEYS));

  /* FIXME: Perhaps more this key handling could be abstracted away,
   * instead of duplicating it in client_keyexchange.c and
   * server_keyexchange.c. */

  /* A hash instance initialized with the key, to be used for key
   * generation */
  hash = kex_build_secret(closure->dh.method->H,
			  closure->dh.exchange_hash,
			  closure->dh.K);
  
  /* Record session id */
  if (!connection->session_id)
    {
      connection->session_id = closure->dh.exchange_hash;
      closure->dh.exchange_hash = NULL; /* For gc */
    }
  
  if (!INSTALL_KEYS(closure->install, connection, hash))
    {
      werror("Installing new keys failed. Hanging up.\n");
      KILL(hash);

      PROTOCOL_ERROR(connection->e, "Refusing to use weak key.");

      return;
    }

  KILL(hash);

  connection->kex_state = KEX_STATE_NEWKEYS;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;

#if DATAFELLOWS_WORKAROUNDS
  if (! (connection->peer_flags & PEER_SEND_NO_DEBUG))
#endif
    send_verbose(connection->write, "Key exchange successful!", 0);

  if (connection->established)
    {
      struct command_continuation *continuation = connection->established;
      connection->established = NULL;
  
      COMMAND_RETURN(continuation, connection);
    }
}

static void
do_init_server_dh(struct keyexchange_algorithm *c,
		  struct ssh_connection *connection,
		  int hostkey_algorithm_atom,
		  /* struct signature_algorithm *ignored, */
		  /* struct keypair *key, */
		  struct lsh_object *extra,
		  struct object_list *algorithms)
{
  CAST(dh_server_exchange, closure, c);
  CAST_SUBTYPE(alist, keys, extra);
  CAST(keypair, key, ALIST_GET(keys,
			       hostkey_algorithm_atom));

  NEW(dh_server, dh);

  if (!key)
    {
      werror("Keypair for for selected signature-algorithm not found!\n");
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
					      "Configuration error"));
      return;
    }

  /* Initialize */
  dh->super.handler = do_handle_dh_init;
  init_diffie_hellman_instance(closure->dh, &dh->dh, connection);

  dh->dh.server_key = lsh_string_dup(key->public);

#if DATAFELLOWS_WORKAROUNDS
  if ( (hostkey_algorithm_atom == ATOM_SSH_DSS)
       && (connection->peer_flags & PEER_SSH_DSS_KLUDGE))
    {
      dh->signer = make_dsa_signer_kludge(key->private);
    }
  else
#endif
    dh->signer = key->private;

  dh->install = make_install_new_keys(1, algorithms);
  
  /* Generate server's secret exponent */
  dh_make_server_secret(&dh->dh);
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_INIT] = &dh->super;

  connection->kex_state = KEX_STATE_IN_PROGRESS;
}


struct keyexchange_algorithm *
make_dh_server(struct diffie_hellman_method *dh)
     /* struct alist *keys) */
{
  NEW(dh_server_exchange, self);

  self->super.init = do_init_server_dh;
  self->dh = dh;
  /* self->keys = keys;  */

  return &self->super;
}

