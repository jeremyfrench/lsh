/* keyexchange.c
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "keyexchange.h"

#include "abstract_io.h"
/* For filter_algorithms */
#include "algorithms.h"
#include "alist.h"
#include "command.h"
#include "connection.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "keyexchange.h.x"
#undef GABA_DEFINE

#include "keyexchange.c.x"

/* Define this to get very frequent re-exchanges */
#ifndef STRESS_KEYEXCHANGE
# define STRESS_KEYEXCHANGE 0
#endif

/* GABA:
   (class
     (name kexinit_handler)
     (super packet_handler)
     (vars
       ; Extra argument for the KEYEXCHANGE_INIT call.
       (extra object lsh_object)
       
       ; Maps names to algorithms. It's dangerous to lookup random atoms
       ; in this table, as not all objects have the same type. This
       ; mapping is used only on atoms that have appeared in *both* the
       ; client's and the server's list of algorithms (of a certain
       ; type), and therefore the remote side can't screw things up.
       (algorithms object alist)))
*/


  
void
send_kexinit(struct ssh_connection *connection)
{
  struct lsh_string *s;
  int mode = connection->flags & CONNECTION_MODE;

  struct kexinit *kex
    = connection->kex.kexinit[mode]
    = MAKE_KEXINIT(connection->kexinit);
  
  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);
  assert(connection->kex.state == KEX_STATE_INIT);

  /* First, disable any key reexchange timer */
  if (connection->key_expire)
    {
      KILL_RESOURCE(connection->key_expire);
      connection->key_expire = NULL;
    }
  
  s = format_kexinit(kex);

  /* Save value for later signing */
#if 0
  debug("send_kexinit: Storing literal_kexinits[%i]\n", mode);
#endif
  
  connection->kex.literal_kexinit[mode] = s; 
  connection_send_kex_start(connection);  

  connection_send_kex(connection, lsh_string_dup(s));

  /* NOTE: This feature isn't fully implemented, as we won't tell
   * the selected key exchange method if the guess was "right". */
  if (kex->first_kex_packet_follows)
    {
      s = kex->first_kex_packet;
      kex->first_kex_packet = NULL;

      connection_send_kex(connection, s);
    }
}


void
disconnect_kex_failed(struct ssh_connection *connection, const char *msg)
{
  EXCEPTION_RAISE
    (connection->e,
     make_protocol_exception(SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			     msg));
}

static void
do_handle_kexinit(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(kexinit_handler, closure, c);
  int mode = connection->flags & CONNECTION_MODE;
  const char *error;

  /* Have we sent a kexinit message already? */
  if (!connection->kex.kexinit[mode])
    send_kexinit(connection);
  
  error = handle_kexinit(&connection->kex, packet, closure->algorithms,
			 mode);

  if (error)
    {
      disconnect_kex_failed(connection, error);
      return;
    }
  {
    CAST_SUBTYPE(keyexchange_algorithm, kex_algorithm,
		 LIST(connection->kex.algorithm_list)[KEX_KEY_EXCHANGE]);

    KEYEXCHANGE_INIT( kex_algorithm,
		      connection,
		      connection->kex.hostkey_algorithm,
		      closure->extra,
		      connection->kex.algorithm_list);
  }
}

struct packet_handler *
make_kexinit_handler(struct lsh_object *extra,
		     struct alist *algorithms)
{
  NEW(kexinit_handler, self);

  self->super.handler = do_handle_kexinit;

  self->extra = extra;
  self->algorithms = algorithms;
  
  return &self->super;
}

/* GABA:
   (class
     (name reexchange_timeout)
     (super lsh_callback)
     (vars
       (connection object ssh_connection)))
*/

static void
do_reexchange_timeout(struct lsh_callback *s)
{
  CAST(reexchange_timeout, self, s);
  assert(!self->connection->send_kex_only);

  verbose("Session key expired. Initiating key re-exchange.\n");
  send_kexinit(self->connection);
}

static void
set_reexchange_timeout(struct ssh_connection *connection,
		       unsigned seconds)
{
  NEW(reexchange_timeout, timeout);

  verbose("Setting session key lifetime to %i seconds\n",
	  seconds);
  timeout->super.f = do_reexchange_timeout;
  timeout->connection = connection;

  assert(!connection->key_expire);
  connection->key_expire = io_callout(&timeout->super,
				      seconds);
  
  remember_resource(connection->resources, connection->key_expire); 
}

/* GABA:
   (class
     (name newkeys_handler)
     (super packet_handler)
     (vars
       (crypto object crypto_instance)
       (mac object mac_instance)
       (compression object compress_instance)))
*/

/* Maximum lifetime for the session keys. Use longer timeout on
 * the server side. */

#if STRESS_KEYEXCHANGE
# define SESSION_KEY_LIFETIME_CLIENT 4
# define SESSION_KEY_LIFETIME_SERVER 14
#else
/* 40 minutes */
# define SESSION_KEY_LIFETIME_CLIENT 2400
/* 90 minutes */
# define SESSION_KEY_LIFETIME_SERVER 5400
#endif

static void
do_handle_newkeys(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(newkeys_handler, closure, c);
  struct simple_buffer buffer;
  unsigned msg_number;

  simple_buffer_init(&buffer, STRING_LD(packet));

  verbose("Received NEWKEYS. Key exchange finished.\n");
  
  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_NEWKEYS)
      && (parse_eod(&buffer)))
    {
      connection->rec_crypto = closure->crypto;
      connection->rec_mac = closure->mac;
      connection->rec_compress = closure->compression;

      reset_kexinit_state(&connection->kex);

      /* Normally, packet entries in the dispatch table must never be
       * NULL, but SSH_MSG_NEWKEYS is handled specially by
       * connection.c:connection_handle_packet. So we could use NULL
       * here, but for uniformity we don't do that. */
      
      connection->dispatch[SSH_MSG_NEWKEYS] = &connection_fail_handler;

      /* Set maximum lifetime for the session keys. Use longer timeout on
       * the server side. */
      
      set_reexchange_timeout
	(connection,
	 ((connection->flags & CONNECTION_MODE) == CONNECTION_SERVER)
	 ? SESSION_KEY_LIFETIME_SERVER : SESSION_KEY_LIFETIME_CLIENT);
      KILL(closure);
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid NEWKEYS message");
}

struct packet_handler *
make_newkeys_handler(struct crypto_instance *crypto,
		     struct mac_instance *mac,
		     struct compress_instance *compression)
{
  NEW(newkeys_handler,self);

  self->super.handler = do_handle_newkeys;
  self->crypto = crypto;
  self->mac = mac;
  self->compression = compression;

  return &self->super;
}

/* Uses the same algorithms for both directions */
/* GABA:
   (class
     (name simple_kexinit)
     (super make_kexinit)
     (vars
       (r object randomness)
       (kex_algorithms object int_list)
       (hostkey_algorithms object int_list)
       (crypto_algorithms object int_list)
       (mac_algorithms object int_list)
       (compression_algorithms object int_list)
       (languages object int_list)))
*/

static struct kexinit *
do_make_simple_kexinit(struct make_kexinit *c)
{
  CAST(simple_kexinit, closure, c);
  NEW(kexinit, kex);

  RANDOM(closure->r, 16, kex->cookie);

  kex->kex_algorithms = closure->kex_algorithms;
  kex->server_hostkey_algorithms = closure->hostkey_algorithms;
  kex->parameters[KEX_ENCRYPTION_CLIENT_TO_SERVER]
    = closure->crypto_algorithms;
  kex->parameters[KEX_ENCRYPTION_SERVER_TO_CLIENT]
    = closure->crypto_algorithms;
  kex->parameters[KEX_MAC_CLIENT_TO_SERVER] = closure->mac_algorithms;
  kex->parameters[KEX_MAC_SERVER_TO_CLIENT] = closure->mac_algorithms;
  kex->parameters[KEX_COMPRESSION_CLIENT_TO_SERVER]
    = closure->compression_algorithms;
  kex->parameters[KEX_COMPRESSION_SERVER_TO_CLIENT]
    = closure->compression_algorithms;
  kex->languages_client_to_server = closure->languages;
  kex->languages_server_to_client = closure->languages;
  kex->first_kex_packet_follows = 0;

  kex->first_kex_packet = NULL;

  return kex;
}

struct make_kexinit *
make_simple_kexinit(struct randomness *r,
		    struct int_list *kex_algorithms,
		    struct int_list *hostkey_algorithms,
		    struct int_list *crypto_algorithms,
		    struct int_list *mac_algorithms,
		    struct int_list *compression_algorithms,
		    struct int_list *languages)
{
  NEW(simple_kexinit, res);

  assert(r->quality == RANDOM_GOOD);
  
  res->super.make = do_make_simple_kexinit;
  res->r = r;
  res->kex_algorithms = kex_algorithms;
  res->hostkey_algorithms = hostkey_algorithms;
  res->crypto_algorithms = crypto_algorithms;
  res->mac_algorithms = mac_algorithms;
  res->compression_algorithms = compression_algorithms;
  res->languages = languages;

  return &res->super;
}

static int
install_keys(struct object_list *algorithms,
	     struct ssh_connection *connection,
	     struct hash_instance *secret)
{
  struct crypto_instance *rec;
  struct crypto_instance *send;
  int is_server = connection->flags & CONNECTION_SERVER;

  assert(LIST_LENGTH(algorithms) == KEX_LIST_LENGTH);

  if (!kex_make_decrypt(&rec, secret, algorithms,
			KEX_ENCRYPTION_SERVER_TO_CLIENT ^ is_server,
			connection->session_id))
    /* Weak or invalid key */
    return 0;

  if (!kex_make_encrypt(&send, secret, algorithms,
			KEX_ENCRYPTION_CLIENT_TO_SERVER ^ is_server,
			connection->session_id))
    {
      KILL(rec);
      return 0;
    }
  
  /* Keys for receiving */
  connection->dispatch[SSH_MSG_NEWKEYS] = make_newkeys_handler
    (rec,
     kex_make_mac(secret, algorithms,
		  KEX_MAC_SERVER_TO_CLIENT ^ is_server,
		  connection->session_id),
     kex_make_inflate(algorithms,
		      KEX_COMPRESSION_SERVER_TO_CLIENT ^ is_server));

  /* Keys for sending */
  /* NOTE: The NEWKEYS-message should have been sent before this
   * is done. */
  connection->send_crypto = send;
  
  connection->send_mac 
    = kex_make_mac(secret, algorithms,
		   KEX_MAC_CLIENT_TO_SERVER ^ is_server,
		   connection->session_id);

  connection->send_compress
    = kex_make_deflate(algorithms,
		       KEX_COMPRESSION_CLIENT_TO_SERVER ^ is_server);
  
  return 1;
}


/* NOTE: Consumes both the exchange_hash and K */
void
keyexchange_finish(struct ssh_connection *connection,
		   struct object_list *algorithms,
		   const struct hash_algorithm *H,
		   struct lsh_string *exchange_hash,
		   struct lsh_string *K)
{
  struct hash_instance *hash;
  
  /* Send a newkeys message, and install a handler for receiving the
   * newkeys message. */

  assert(connection->send_kex_only);
  connection_send_kex(connection, format_newkeys());
  
  /* A hash instance initialized with the key, to be used for key
   * generation */
  hash = kex_build_secret(H, exchange_hash, K);
  
  /* Record session id */
  if (!connection->session_id)
    connection->session_id = exchange_hash;
  else
    lsh_string_free(exchange_hash);
  
  if (!install_keys(algorithms, connection, hash))
    {
      werror("Installing new keys failed. Hanging up.\n");
      KILL(hash);

      PROTOCOL_ERROR(connection->e, "Refusing to use weak key.");

      return;
    }

  KILL(hash);

  /* If any messages were queued during the key exchange, send them
   * now. */
  connection_send_kex_end(connection);
  
  connection->kex.state = KEX_STATE_NEWKEYS;
}
