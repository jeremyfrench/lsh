/* lshd_keyexchange.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#include "lshd.h"

#include "format.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd_keyexchange.c.x"

void
lshd_send_kexinit(struct lshd_connection *connection)
{
  struct lsh_string *s;
  struct kexinit *kex
    = connection->kex.kexinit[1]
    = MAKE_KEXINIT(connection->config->kexinit);
  
  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.state == KEX_STATE_INIT);

  /* FIXME: Deal with timeout */
  
  s = format_kexinit(kex);
  connection->kex.literal_kexinit[1] = lsh_string_dup(s); 
  connection_write_packet(connection, s);

  if (kex->first_kex_packet)
    fatal("Not implemented\n");
}

DEFINE_PACKET_HANDLER(lshd_kexinit_handler, connection, packet)
{
  const char *error;

  if (!connection->kex.kexinit[1])
    lshd_send_kexinit(connection);
  
  error = handle_kexinit(&connection->kex, packet,
			 connection->config->algorithms, 1);

  if (error)
    {
      connection_disconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, error);
      return;
    }

  {
    CAST_SUBTYPE(lshd_packet_handler, handler,
		 LIST(connection->kex.algorithm_list)[KEX_KEY_EXCHANGE]);
    connection->kex_handler = handler;
  }
}

/* FIXME: Overlaps with keyexchange.c. */
/* GABA:
   (class
     (name lshd_newkeys_handler)
     (super lshd_packet_handler)
     (vars
       (crypto object crypto_instance)
       (mac object mac_instance)
       (compression object compress_instance)))
*/

/* FIXME: Move newkeys handling to transport_read.c? */
static void
lshd_newkeys_handler(struct lshd_packet_handler *s,
		     struct lshd_connection *connection,
		     struct lsh_string *packet)
{
  CAST(lshd_newkeys_handler, self, s);
  struct simple_buffer buffer;
  unsigned msg_number;

  assert(connection->kex.state = KEX_STATE_NEWKEYS);
	 
  simple_buffer_init(&buffer, STRING_LD(packet));

  verbose("Received NEWKEYS. Key exchange finished.\n");
  
  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_NEWKEYS)
      && (parse_eod(&buffer)))
    {
      struct transport_read_state *reader = &connection->reader->super;
      reader->super.header_length
	= self->crypto ? self->crypto->block_size : 8;

      reader->crypto = self->crypto;
      reader->mac = self->mac;
      reader->compression = self->compression;
      
      reset_kexinit_state(&connection->kex);
      if (connection->service_state == SERVICE_DISABLED)
	connection->service_state = SERVICE_ENABLED;
    }
  else
    connection_error(connection, "Invalid NEWKEYS message");
}

static struct lshd_packet_handler *
make_lshd_newkeys_handler(struct crypto_instance *crypto,
			  struct mac_instance *mac,
			  struct compress_instance *compression)
{
  NEW(lshd_newkeys_handler,self);

  self->super.handler = lshd_newkeys_handler;
  self->crypto = crypto;
  self->mac = mac;
  self->compression = compression;

  return &self->super;
}

/* Consumes exchange_hash and K */
static int
lshd_install_keys(struct lshd_connection *connection,
		  const struct hash_algorithm *H,
		  struct lsh_string *exchange_hash,
		  struct lsh_string *K)
{
  struct hash_instance *secret;
  struct crypto_instance *rec;
  struct crypto_instance *send;
  struct object_list *algorithms = connection->kex.algorithm_list;
  
  connection_write_packet(connection, format_newkeys());
  secret = kex_build_secret(H, exchange_hash, K);

  if (!connection->session_id)
    connection->session_id = exchange_hash;
  else
    lsh_string_free(exchange_hash);
  
  assert(LIST_LENGTH(algorithms) == KEX_LIST_LENGTH);

  if (!kex_make_decrypt(&rec, secret, algorithms,
			KEX_ENCRYPTION_CLIENT_TO_SERVER,
			connection->session_id))
    /* Weak or invalid key */
    return 0;

  if (!kex_make_encrypt(&send, secret, algorithms,
			KEX_ENCRYPTION_SERVER_TO_CLIENT,
			connection->session_id))
    return 0;

  connection->newkeys_handler =
    make_lshd_newkeys_handler(rec,
			      kex_make_mac(secret, algorithms,
					   KEX_MAC_CLIENT_TO_SERVER,
					   connection->session_id),
			      kex_make_inflate(algorithms,
					       KEX_COMPRESSION_SERVER_TO_CLIENT));

  /* Keys for sending */
  connection->send_crypto = send;
  
  connection->send_mac 
    = kex_make_mac(secret, algorithms,
		   KEX_MAC_SERVER_TO_CLIENT,
		   connection->session_id);

  connection->send_compress
    = kex_make_deflate(algorithms,
		       KEX_COMPRESSION_SERVER_TO_CLIENT);

  connection->kex.state = KEX_STATE_NEWKEYS;
  
  return 1;
}

/* GABA:
   (class
     (name lshd_dh_init_handler)
     (super lshd_packet_handler)
     (vars
       (dh object dh_method)))
*/

static void
lshd_dh_init_handler(struct lshd_packet_handler *s,
		     struct lshd_connection *connection,
		     struct lsh_string *packet)
{
  CAST(lshd_dh_init_handler, self, s);
  struct dh_instance instance;

  connection->kex_handler = NULL;
  
  /* FIXME: The server side really doesn't need any state */
  init_dh_instance(self->dh, &instance, &connection->kex);

  dh_make_server_secret(&instance);
  if (dh_process_client_msg(&instance, packet))
    {
      CAST(keypair, keypair,
	   ALIST_GET(connection->config->keys,
		     connection->kex.hostkey_algorithm));

      if (!keypair)
	fatal("Internal error: No key available for selected host key algorithm\n");
      
      connection_write_packet(connection,
			      dh_make_server_msg(&instance, keypair->public,
						 connection->kex.hostkey_algorithm,
						 keypair->private));
      
      /* Derive keys */
      lshd_install_keys(connection, self->dh->H,
			instance.exchange_hash, instance.K);

      instance.K = instance.exchange_hash = NULL;      
    }
  else
    connection_error(connection, "Bad KEXDH_INIT message");

  dh_instance_free(&instance);
  
}

struct lshd_packet_handler *
make_lshd_dh_handler(struct dh_method *method)
{
  NEW(lshd_dh_init_handler, self);
  self->super.handler = lshd_dh_init_handler;
  self->dh = method;

  return &self->super;
}
