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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "client_keyexchange.h"

#include "atoms.h"
#include "debug.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "client_keyexchange.h.x"
#undef GABA_DEFINE

#include "client_keyexchange.c.x"

/* GABA:
   (class
     (name dh_client_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object diffie_hellman_method)
       (verifier object lookup_verifier)))
*/

/* Handler for the kex_dh_reply message */
/* GABA:
   (class
     (name dh_client)
     (super packet_handler)
     (vars
       (dh struct diffie_hellman_instance)
       (verifier object lookup_verifier)
       (install object install_keys)))
       ;;; (finished object ssh_service)))
*/
    
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
   * handler for receiving the newkeys message. */

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
  
  if (!INSTALL_KEYS(closure->install, connection, hash))
    {
      werror("Installing new keys failed. Hanging up.\n");
      KILL(hash);
      /* FIXME: Send a disconnect message */
      return LSH_FAIL | LSH_DIE;
    }

  KILL(hash);

  connection->dispatch[SSH_MSG_KEXDH_REPLY] = connection->fail;
  connection->kex_state = KEX_STATE_NEWKEYS;
  
  res |= send_verbose(connection->write, "Key exchange successful!", 0);
  if (LSH_CLOSEDP(res) || !connection->established)
    return res;

  return res | COMMAND_RETURN(connection->established, connection);
}

static int do_init_client_dh(struct keyexchange_algorithm *c,
		             struct ssh_connection *connection,
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
  dh->install = make_install_new_keys(0, algorithms);
  
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
  
  self->super.init = do_init_client_dh;
  self->dh = dh;
  self->verifier = verifier;

  return &self->super;
}

