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
#include "sexp_commands.h"
#include "srp.h"
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
       (dh object dh_method)))
*/

/* Handler for the kex_dh_reply message */
/* GABA:
   (class
     (name dh_server)
     (super packet_handler)
     (vars
       (dh struct dh_instance)
       (signer object signer)
       (algorithms object object_list)))
*/

static void
do_handle_dh_init(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(dh_server, closure, c);
  struct lsh_string *hash;
  int res;
  
  trace("handle_dh_init()\n");

  res = dh_process_client_msg(&closure->dh, packet);
  lsh_string_free(packet);
  
  if (!res)
    {
      disconnect_kex_failed(connection, "Bad dh-init\r\n");
      return;
    }
  
  /* Send server's message, to complete key exchange */
  C_WRITE(connection,
	  dh_make_server_msg(&closure->dh,
			     closure->signer));

  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;

  hash = closure->dh.exchange_hash;
  closure->dh.exchange_hash = NULL; /* For gc */

  keyexchange_finish(connection, closure->algorithms,
		     closure->dh.method->H,
		     hash,
		     ssh_format("%n", closure->dh.K));

  /* Try to purge information about the key exchange */
  KILL(closure);
}

static void
do_init_server_dh(struct keyexchange_algorithm *c,
		  struct ssh_connection *connection,
		  int hostkey_algorithm_atom,
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
      disconnect_kex_failed(connection, "Configuration error");
      return;
    }

  /* Initialize */
  dh->super.handler = do_handle_dh_init;
  init_dh_instance(closure->dh, &dh->dh, connection);

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

  dh->algorithms = algorithms;
  
  /* Generate server's secret exponent */
  dh_make_server_secret(&dh->dh);
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXDH_INIT] = &dh->super;

  connection->kex_state = KEX_STATE_IN_PROGRESS;
}


struct keyexchange_algorithm *
make_dh_server(struct dh_method *dh)
{
  NEW(dh_server_exchange, self);

  self->super.init = do_init_server_dh;
  self->dh = dh;

  return &self->super;
}


#if WITH_SRP
/* SRP key exchange */

/* GABA:
   (class
     (name srp_server_instance)
     (vars
       (dh struct dh_instance)
       (algorithms object object_list)
       (db object user_db)
       (user object lsh_user)
       (entry object srp_entry)))
*/

/* GABA:
   (class
     (name srp_server_handler)
     (super packet_handler)
     (vars
       (srp object srp_server_instance)))
*/

static void
do_srp_server_proof_handler(struct packet_handler *s,
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  CAST(srp_server_handler, self, s);

  struct lsh_string *response = srp_process_client_proof(&self->srp->dh, packet);
  lsh_string_free(packet);

  connection->dispatch[SSH_MSG_KEXSRP_PROOF] = connection->fail;
  
  if (response)
    {
      struct lsh_string *hash;
      C_WRITE(connection, response);

      hash = self->srp->dh.exchange_hash;
      self->srp->dh.exchange_hash = NULL; /* For gc */

      keyexchange_finish(connection, self->srp->algorithms,
			 self->srp->dh.method->H,
			 hash,
			 ssh_format("%n", self->srp->dh.K));
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_KEXSRP_PROOF message");

  /* Try to purge information about the key exchange */
  KILL(self->srp);
  KILL(self);
}

static struct packet_handler *
make_srp_server_proof_handler(struct srp_server_instance *srp)
{
  NEW(srp_server_handler, self);
  self->super.handler = do_srp_server_proof_handler;
  self->srp = srp;

  return &self->super;
}

static void
do_exc_srp(struct exception_handler *e,
	   const struct exception *x)
{
  EXCEPTION_RAISE(e->parent,
		  make_protocol_exception(SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
					  x->msg));
}

/* Invoked after that we have read an sexp that represents a user's verifier */
/* GABA:
   (class
     (name srp_init_continuation)
     (super command_continuation)
     (vars
       (srp object srp_server_instance)
       (connection object ssh_connection)))
*/

static void
do_srp_init_continuation(struct command_continuation *s,
			 struct lsh_object *a)
{
  CAST(srp_init_continuation, self, s);
  CAST_SUBTYPE(sexp, e, a);

  self->srp->entry = make_srp_entry(self->srp->user->name, e);

  if (!self->srp->entry)
    {
      disconnect_kex_failed(self->connection, "Invalid SRP verifier");
      return;
    }

  C_WRITE(self->connection, srp_make_reply_msg(&self->srp->dh, self->srp->entry));
  self->connection->dispatch[SSH_MSG_KEXSRP_PROOF] = make_srp_server_proof_handler(self->srp);
}

static struct command_continuation *
make_server_srp_continuation(struct srp_server_instance *srp,
			     struct ssh_connection *connection)
{
  NEW(srp_init_continuation, self);
  self->super.c = do_srp_init_continuation;
  self->srp = srp;
  self->connection = connection;

  return &self->super;
}

static void
do_handle_srp_init(struct packet_handler *s,
		   struct ssh_connection *connection,
		   struct lsh_string *packet)
{
  CAST(srp_server_handler, self, s);
  struct lsh_string *name = srp_process_init_msg(&self->srp->dh, packet);
  struct exception_handler *e;
  
  connection->dispatch[SSH_MSG_KEXSRP_INIT] = connection->fail;
  
  if (!name)
    {
      PROTOCOL_ERROR(connection->e, "Invalid SSH_MSG_KEXSRP_INIT message");
      return;
    }

  self->srp->user = USER_LOOKUP(self->srp->db, name, 1);
  if (!self->srp->user)
    {
      EXCEPTION_RAISE(connection->e,
		      make_protocol_exception(SSH_DISCONNECT_ILLEGAL_USER_NAME, NULL));
      return;
    }

  /* Try opening the user's ~/.lsh/srp-verifier */
  e = make_exception_handler(do_exc_srp, connection->e, HANDLER_CONTEXT);
  
  USER_READ_FILE(self->srp->user, "srp-verifier", 1,		 
		 make_apply(make_read_sexp_command(SEXP_CANONICAL, 0),
			    make_server_srp_continuation(self->srp, connection),
			    e),
		 e);
}

static struct packet_handler *
make_srp_init_handler(struct srp_server_instance *srp)
{
  NEW(srp_server_handler, self);
  self->super.handler = do_handle_srp_init;
  self->srp = srp;

  return &self->super;
}

/* GABA:
   (class
     (name srp_server_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object dh_method)
       (db object user_db)))
*/

static void
do_init_server_srp(struct keyexchange_algorithm *s,
		   struct ssh_connection *connection,
		   int hostkey_algorithm_atom UNUSED,
		   struct lsh_object *extra UNUSED,
		   struct object_list *algorithms)
{
  CAST(srp_server_exchange, self, s);

  NEW(srp_server_instance, srp);

  /* Initialize */
  init_dh_instance(self->dh, &srp->dh, connection);

  /* FIXME: These are not needed here. */
  srp->dh.server_key = NULL;
  srp->dh.signature = NULL;

  srp->algorithms = algorithms;
  srp->db = self->db;
  srp->user = NULL;
  srp->entry = NULL;
  
  /* Install handler */
  connection->dispatch[SSH_MSG_KEXSRP_INIT] = make_srp_init_handler(srp);

  connection->kex_state = KEX_STATE_IN_PROGRESS;
}

struct keyexchange_algorithm *
make_srp_server(struct dh_method *dh,
		struct user_db *db)
{
  NEW(srp_server_exchange, self);

  assert(dh->G->add);
  assert(dh->G->subtract);
  
  self->super.init = do_init_server_srp;
  self->dh = dh;
  self->db = db;
  
  return &self->super;
}

#endif /* WITH_SRP */
