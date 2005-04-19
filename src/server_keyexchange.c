/* server_keyexchange.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Niels M�ller
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

#include "publickey_crypto.h"

#include "atoms.h"
#include "command.h"
#include "crypto.h"
#include "format.h"
#include "lsh_string.h"
#include "sexp.h"
#include "ssh.h"
#include "transport.h"
#include "werror.h"
#include "xalloc.h"

#include "server_keyexchange.c.x"

/* GABA:
   (class
     (name server_dh_exchange)
     (super keyexchange_algorithm)
     (vars
       (params struct dh_params)
       (keys object alist)))
*/

/* Handler for the kex_dh_reply message */
/* GABA:
   (class
     (name server_dh_handler)
     (super transport_handler)
     (vars
       (dh struct dh_state)
       (key object keypair)))
*/

static void
server_dh_handler(struct transport_handler *s,
		  struct transport_connection *connection,
		  uint32_t length, const uint8_t *packet)
{
  CAST(server_dh_handler, self, s);
  struct simple_buffer buffer;
  mpz_t tmp;
  
  trace("handle_dh_init\n");

  assert(length > 0);
  if (packet[0] != SSH_MSG_KEXDH_INIT)
    {
      transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			   "No KEXDH_INIT message.");
      return;
    }

  simple_buffer_init(&buffer, length-1, packet+1);

  if (parse_bignum(&buffer, self->dh.e, self->dh.params->limit)
      && (mpz_cmp_ui(self->dh.e, 1) > 0)
      && (mpz_cmp(self->dh.e, self->dh.params->modulo) < 0)
      && parse_eod(&buffer) )
    {
      mpz_init(tmp);
      mpz_powm(tmp, self->dh.params->generator, self->dh.secret, self->dh.params->modulo);
      self->dh.K = ssh_format("%ln", tmp);
      mpz_clear(tmp);
      
      dh_hash_update(&self->dh, ssh_format("%S", self->key->public), 1);
      dh_hash_digest(&self->dh);

      /* Send server's message, to complete key exchange */      
      transport_send_packet(connection,
			    ssh_format("%c%S%n%fS",
				       SSH_MSG_KEXDH_REPLY,
				       self->key->public,
				       self->dh.f, SIGN(self->key->private,
							self->key->type,
							lsh_string_length(self->dh.exchange_hash),
							lsh_string_data(self->dh.exchange_hash))));
      transport_keyexchange_finish(connection,
				   self->dh.params->H,
				   self->dh.exchange_hash,
				   self->dh.K);
      self->dh.exchange_hash = NULL;
      self->dh.K = NULL;
    }
  else
    transport_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			 "Invalid KEXDH_INIT message.");
}  

static struct transport_handler *
server_dh_init(struct keyexchange_algorithm *s,
	       struct randomness *random,
	       struct kexinit_state *kex)
{
  CAST(server_dh_exchange, self, s);
  CAST(keypair, key, ALIST_GET(self->keys, kex->hostkey_algorithm));

  if (!key)
    {
      werror("Keypair for for selected signature-algorithm not found!\n");
      return NULL;
    }
  else
    {
      NEW(server_dh_handler, handler);
      
      /* Initialize */
      handler->super.handler = server_dh_handler;
      init_dh_state(&handler->dh, &self->params, kex);

      handler->key = key;

      /* Generate server's secret exponent */
      dh_generate_secret(&self->params, random, handler->dh.secret, handler->dh.f);
  
      /* Return handler */
      return &handler->super;
    }
}

static struct keyexchange_algorithm *
make_server_dh_exchange(void (*init)(struct dh_params *params,
				     const struct hash_algorithm *H),
			const struct hash_algorithm *H,
			struct alist *keys)
{
  NEW(server_dh_exchange, self);
  init(&self->params, H);
  self->super.init = server_dh_init;
  self->keys = keys;

  return &self->super;
}

struct keyexchange_algorithm *
make_server_dh_group1_sha1(struct alist *keys)
{
  return make_server_dh_exchange(init_dh_group1, &crypto_sha1_algorithm, keys);
}

struct keyexchange_algorithm *
make_server_dh_group14_sha1(struct alist *keys)
{
  return make_server_dh_exchange(init_dh_group14, &crypto_sha1_algorithm, keys);
}
