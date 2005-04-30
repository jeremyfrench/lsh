/* client_keyexchange.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "keyexchange.h"

#include "atoms.h"
#include "command.h"
#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "parse.h"
#include "ssh.h"
#include "transport.h"
#include "werror.h"
#include "xalloc.h"

#include "client_keyexchange.c.x"

/* GABA:
   (class
     (name client_dh_exchange)
     (super keyexchange_algorithm)
     (vars
       (params const object dh_params)
       (db object lookup_verifier)))
*/

/* Handler for the KEXDH_REPLY message */
/* GABA:
   (class
     (name client_dh_handler)
     (super transport_handler)
     (vars
       (dh struct dh_state)
       (db object lookup_verifier)
       (hostkey_algorithm . int)))
*/

static void
client_dh_handler(struct transport_handler *s,
		  struct transport_connection *connection,
		  uint32_t length, const uint8_t *packet)
{
  CAST(client_dh_handler, self, s);
  struct simple_buffer buffer;
  uint32_t key_length;
  const uint8_t *key;
  uint32_t signature_length;
  const uint8_t *signature;
  
  trace("client_dh_handler\n");

  assert(length > 0);
  if (packet[0] != SSH_MSG_KEXDH_REPLY)
    {
      transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			   "No KEXDH_REPLY message.");
      return;
    }

  simple_buffer_init(&buffer, length-1, packet+1);
  if (parse_string(&buffer, &key_length, &key)
      && parse_bignum(&buffer, self->dh.f, self->dh.params->limit)
      && (mpz_cmp_ui(self->dh.f, 1) > 0)
      && (mpz_cmp(self->dh.f, self->dh.params->modulo) < 0)
      && parse_string(&buffer, &signature_length, &signature)
      && parse_eod(&buffer))
    {
      mpz_t tmp;
      
      struct verifier *v = LOOKUP_VERIFIER(self->db, self->hostkey_algorithm,
					   key_length, key);
      if (!v)
	{
	  transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			       "Unknown server host key");
	  return;
	}

      /* Construct key */
      mpz_init(tmp);

      mpz_powm(tmp, self->dh.f, self->dh.secret, self->dh.params->modulo);
      self->dh.K = ssh_format("%ln", tmp);
      mpz_clear(tmp);

      debug("Session key: %xS\n", self->dh.K);

      /* FIXME: Unnecessary allocation */
      dh_hash_update(&self->dh, ssh_format("%s", key_length, key), 1);
      dh_hash_digest(&self->dh);

      debug("Exchange hash: %xS\n", self->dh.exchange_hash);
      
      if (!VERIFY(v, self->hostkey_algorithm,
		  lsh_string_length(self->dh.exchange_hash),
		  lsh_string_data(self->dh.exchange_hash),
		  signature_length, signature))
	{
	  transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			       "Invalid server signature");
	  return;	 
	}

      transport_keyexchange_finish(connection,
				   self->dh.params->H,
				   self->dh.exchange_hash,
				   self->dh.K);
      self->dh.exchange_hash = NULL;
      self->dh.K = NULL;      
    }
  else
    transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			 "Invalid KEXDH_REPLY message");
}

static struct transport_handler *
client_dh_init(struct keyexchange_algorithm *s,
	       struct transport_connection *connection)
{
  CAST(client_dh_exchange, self, s);
  NEW(client_dh_handler, handler);

  /* Initialize */
  init_dh_state(&handler->dh, self->params, &connection->kex);  

  handler->super.handler = client_dh_handler;
  handler->db = self->db;
  handler->hostkey_algorithm = connection->kex.hostkey_algorithm;
  
  /* Generate clients 's secret exponent */
  dh_generate_secret(self->params, connection->ctx->random,
		     handler->dh.secret, handler->dh.e);

  /* Send client's message */
  transport_send_packet(connection, 1,
			ssh_format("%c%n", SSH_MSG_KEXDH_INIT, handler->dh.e));

  /* Install handler */
  return &handler->super;
}


struct keyexchange_algorithm *
make_client_dh_exchange(const struct dh_params *params,
			struct lookup_verifier *db)
{
  NEW(client_dh_exchange, self);

  self->super.init = client_dh_init;
  self->params = params;
  self->db = db;
  
  return &self->super;
}
