/* keyexchange.c
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

#include "keyexchange.h"

#include "abstract_io.h"
#include "alist.h"
#include "connection.h"
#include "disconnect.h"
#include "format.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>
#include <assert.h>

#define GABA_DEFINE
#include "keyexchange.h.x"
#undef GABA_DEFINE

#include "keyexchange.c.x"

/* GABA:
   (class
     (name kexinit_handler)
     (super packet_handler)
     (vars
       (type simple int)
       (init object make_kexinit)

       ; Maps names to algorithms. It's dangerous to lookup random atoms
       ; in this table, as not all objects have the same type. This
       ; mapping is used only on atoms that have appeared in *both* the
       ; client's and the server's list of algorithms (of a certain
       ; type), and therefore the remote side can't screw things up.
       (algorithms object alist)))

       ;;; (finished object ssh_service)))
*/

#define NLISTS 10

/* Arbitrary limit on list length */
#define KEXINIT_MAX_ALGORITMS 47

static struct kexinit *parse_kexinit(struct lsh_string *packet)
{
  NEW(kexinit, res);
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 reserved;
  
  struct int_list *lists[NLISTS];
  int i;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!parse_uint8(&buffer, &msg_number)
      || (msg_number != SSH_MSG_KEXINIT) )
    {
      KILL(res);
      return NULL;
    }

  if (!parse_octets(&buffer, 16, res->cookie))
    {
      KILL(res);
      return NULL;
    }
  
  for (i = 0; i<NLISTS; i++)
    {
      if ( !(lists[i] = parse_atom_list(&buffer, KEXINIT_MAX_ALGORITMS)))
	break;
    }

  if ( (i<NLISTS)
       || !parse_boolean(&buffer, &res->first_kex_packet_follows)
       || !parse_uint32(&buffer, &reserved)
       || reserved || !parse_eod(&buffer) )
    {
      /* Bad format */
      int j;
      for (j = 0; j<i; j++)
	KILL(lists[i]);
      KILL(res);
      return NULL;
    }
  
  res->kex_algorithms = lists[0];
  res->server_hostkey_algorithms = lists[1];

  for (i=0; i<KEX_PARAMETERS; i++)
    res->parameters[i] = lists[2 + i];

  res->languages_client_to_server = lists[8];
  res->languages_server_to_client = lists[9];

  return res;
}

struct lsh_string *format_kex(struct kexinit *kex)
{
  return ssh_format("%c%ls%A%A%A%A%A%A%A%A%A%A%c%i",
		    SSH_MSG_KEXINIT,
		    16, kex->cookie,
		    kex->kex_algorithms,
		    kex->server_hostkey_algorithms,
		    kex->parameters[KEX_ENCRYPTION_CLIENT_TO_SERVER],
		    kex->parameters[KEX_ENCRYPTION_SERVER_TO_CLIENT],
		    kex->parameters[KEX_MAC_CLIENT_TO_SERVER],
		    kex->parameters[KEX_MAC_SERVER_TO_CLIENT],
		    kex->parameters[KEX_COMPRESSION_CLIENT_TO_SERVER],
		    kex->parameters[KEX_COMPRESSION_SERVER_TO_CLIENT],
		    kex->languages_client_to_server,
		    kex->languages_server_to_client,
		    kex->first_kex_packet_follows, 0);
}
  
void
initiate_keyexchange(struct ssh_connection *connection,
		     int mode)
{
  struct lsh_string *s;
  struct kexinit *kex = connection->kexinits[mode];

  assert(kex->first_kex_packet_follows == !!kex->first_kex_packet);

  s = format_kex(kex);

  /* Save value for later signing */
  connection->literal_kexinits[mode] = s; 

  C_WRITE(connection, lsh_string_dup(s));

  if (kex->first_kex_packet_follows)
    {
      s = kex->first_kex_packet;
      kex->first_kex_packet = NULL;

      C_WRITE(connection, s);
    }
}

static int select_algorithm(struct int_list *server_list,
			    struct int_list *client_list)
{
  /* FIXME: This quadratic complexity algorithm should do as long as
   * the lists are short. To avoid DOS-attacks, ther should probably
   * be some limit on the list lengths. */
  unsigned i, j;

  for(i = 0; i < LIST_LENGTH(client_list); i++)
    {
      int a = LIST(client_list)[i];
      if (!a)
	/* Unknown algorithm */
	continue;
      for(j = 0; j < LIST_LENGTH(server_list); j++)
	if (a == LIST(server_list)[j])
	  return a;
    }

  return 0;
}

void disconnect_kex_failed(struct ssh_connection *connection, const char *msg)
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
  struct kexinit *msg = parse_kexinit(packet);

  int kex_algorithm_atom;
  int hostkey_algorithm_atom;

  int parameters[KEX_PARAMETERS];
  struct object_list *algorithms;

  int i;

  if (!msg)
    {
      PROTOCOL_ERROR(connection->e, "Invalid KEXINIT message.");
      return;
    }

  /* Save value for later signing */
  connection->literal_kexinits[!closure->type] = packet;
  
  connection->kexinits[!closure->type] = msg;
  
  /* Have we sent a kexinit message? */
  if (!connection->kexinits[closure->type])
    {
      struct lsh_string *packet;
      struct kexinit *sent = MAKE_KEXINIT(closure->init);
      connection->kexinits[closure->type] = sent;
      packet = format_kex(sent);
      connection->literal_kexinits[closure->type] = lsh_string_dup(packet); 
      
      C_WRITE(connection, packet);
    }

  /* Select key exchange algorithms */

  /* FIXME: Look at the hostkey algorithm as well. */
  if (LIST(connection->kexinits[0]->kex_algorithms)[0]
      == LIST(connection->kexinits[1]->kex_algorithms)[0])
    {
      /* Use this algorithm */
      kex_algorithm_atom = LIST(connection->kexinits[0]->kex_algorithms)[0];
    }
  else
    {
      if (msg->first_kex_packet_follows)
	{
	  /* Wrong guess */
	  connection->kex_state = KEX_STATE_IGNORE;
	}

      /* FIXME: Ignores that some keyexchange algorithms require
       * certain features of the host key algorithms. */
      
      kex_algorithm_atom
	= select_algorithm(connection->kexinits[0]->kex_algorithms,
			   connection->kexinits[1]->kex_algorithms);

      if  (!kex_algorithm_atom)
	{
	  disconnect_kex_failed(connection,
				"No common key exchange method.\r\n");
	  return;
	}
    }
  hostkey_algorithm_atom
    = select_algorithm(connection->kexinits[0]->server_hostkey_algorithms,
		       connection->kexinits[1]->server_hostkey_algorithms);

#if 0
#if DATAFELLOWS_WORKAROUNDS
  if ( (hostkey_algorithm_atom == ATOM_SSH_DSS)
       && (connection->peer_flags & PEER_SSH_DSS_KLUDGE))
    {
      hostkey_algorithm_atom = ATOM_SSH_DSS_KLUDGE;
    }
#endif /* DATAFELLOWS_WORKAROUNDS */
#endif
  
  for(i = 0; i<KEX_PARAMETERS; i++)
    {
      parameters[i]
	= select_algorithm(connection->kexinits[0]->parameters[i],
			   connection->kexinits[1]->parameters[i]);
      
      if (!parameters[i])
	{
	  disconnect_kex_failed(connection, "");
	  return;
	}
    }
  
  algorithms = alloc_object_list(KEX_PARAMETERS);
  
  for (i = 0; i<KEX_PARAMETERS; i++)
    LIST(algorithms)[i] = ALIST_GET(closure->algorithms, parameters[i]);

  {
    CAST_SUBTYPE(keyexchange_algorithm, kex_algorithm,
		 ALIST_GET(closure->algorithms, kex_algorithm_atom));
    CAST_SUBTYPE(signature_algorithm, hostkey_algorithm,
		 ALIST_GET(closure->algorithms,
			   hostkey_algorithm_atom));
    KEYEXCHANGE_INIT( kex_algorithm,
		      connection,
		      hostkey_algorithm_atom,
		      hostkey_algorithm,
		      algorithms);
  }
}

struct packet_handler *make_kexinit_handler(int type,
					    struct make_kexinit *init,
					    struct alist *algorithms)
{
  NEW(kexinit_handler, self);

  self->super.handler = do_handle_kexinit;

  self->type = type;
  self->init = init;
  self->algorithms = algorithms;
  
  return &self->super;
}

#define IV_TYPE(t) ((t) + 4)

static struct lsh_string *kex_make_key(struct hash_instance *secret,
				       UINT32 key_length,
				       int type,
				       struct lsh_string *session_id)
{
  /* Indexed by the KEX_* values */
  static /* const */ char *tags = "CDEFAB";
  
  struct lsh_string *key;
  struct hash_instance *hash;
  UINT8 *digest;
  
  key = lsh_string_alloc(key_length);

  debug("\nConstructing session key of type %i\n", type);
  
  if (!key_length)
    return key;
  
  hash = HASH_COPY(secret);
  digest = alloca(hash->hash_size);

  HASH_UPDATE(hash, 1, tags + type); 
  HASH_UPDATE(hash, session_id->length, session_id->data);
  HASH_DIGEST(hash, digest);

  /* Is one digest large anough? */
  if (key_length <= hash->hash_size)
    memcpy(key->data, digest, key_length);

  else
    {
      unsigned left = key_length;
      UINT8 *dst = key->data;
      
      KILL(hash);
      hash = HASH_COPY(secret);
      
      for (;;)
	{
	  /* The n:th time we enter this loop, digest holds K_n (using
	   * the notation of section 5.2 of the ssh "transport"
	   * specification), and hash contains the hash state
	   * corresponding to
	   *
	   * H(secret | K_1 | ... | K_{n-1}) */

	  struct hash_instance *tmp;
	  
	  /* Append digest to the key data. */
	  memcpy(dst, digest, hash->hash_size);
	  dst += hash->hash_size;
	  left -= hash->hash_size;

	  /* And to the hash state */
	  HASH_UPDATE(hash, hash->hash_size, digest);

	  if (left <= hash->hash_size)
	    break;
	  
	  /* Get a new digest, without disturbing the hash object (as
	   * we'll need it again). We use another temporary hash for
	   * extracting the digest. */

	  tmp = HASH_COPY(hash);
	  HASH_DIGEST(tmp, digest);
	  KILL(tmp);
	}

      /* Get the final digest, and use some of it for the key. */
      HASH_DIGEST(hash, digest);
      memcpy(dst, digest, left);
    }
  KILL(hash);

  debug("Expanded key: %xs",
	key->length, key->data);

  return key;
}
  
struct crypto_instance *kex_make_encrypt(struct hash_instance *secret,
					 struct object_list *algorithms,
					 int type,
					 struct lsh_string *session_id)
{
  CAST_SUBTYPE(crypto_algorithm, algorithm, LIST(algorithms)[type]);
    
  struct lsh_string *key;
  struct lsh_string *iv = NULL;
  struct crypto_instance *crypto;

  assert(LIST_LENGTH(algorithms) == KEX_PARAMETERS);

  if (!algorithm)
    return NULL;

  key = kex_make_key(secret, algorithm->key_size,
					type, session_id);

  if (algorithm->iv_size)
    iv = kex_make_key(secret, algorithm->iv_size,
		      IV_TYPE(type), session_id);
  
  crypto = MAKE_ENCRYPT(algorithm, key->data,
			iv ? iv->data : NULL);

  lsh_string_free(key);
  lsh_string_free(iv);
  
  return crypto;
}

struct crypto_instance *kex_make_decrypt(struct hash_instance *secret,
					 struct object_list *algorithms,
					 int type,
					 struct lsh_string *session_id)
{
  CAST_SUBTYPE(crypto_algorithm, algorithm, LIST(algorithms)[type]);

  struct lsh_string *key;
  struct lsh_string *iv = NULL;
  struct crypto_instance *crypto;

  assert(LIST_LENGTH(algorithms) == KEX_PARAMETERS);

  if (!algorithm)
    return NULL;
  
  key = kex_make_key(secret, algorithm->key_size,
		     type, session_id);

  if (algorithm->iv_size)
    iv = kex_make_key(secret, algorithm->iv_size,
		      IV_TYPE(type), session_id);
  
  crypto = MAKE_DECRYPT(algorithm, key->data, iv ? iv->data : NULL);

  lsh_string_free(key);
  lsh_string_free(iv);
  
  return crypto;
}

struct mac_instance *kex_make_mac(struct hash_instance *secret,
				  struct object_list *algorithms,
				  int type,
				  struct lsh_string *session_id)
{
  CAST_SUBTYPE(mac_algorithm, algorithm, LIST(algorithms)[type]);

  struct mac_instance *mac;
  struct lsh_string *key;

  assert(LIST_LENGTH(algorithms) == KEX_PARAMETERS);
  
  if (!algorithm)
    return NULL;

  key = kex_make_key(secret, algorithm->key_size,
		     type, session_id);

  mac = MAKE_MAC(algorithm, key->data);

  lsh_string_free(key);
  return mac;
}

static struct compress_instance *kex_make_deflate(struct object_list *algorithms,
						   int type)
{
  CAST_SUBTYPE(compress_algorithm, algorithm, LIST(algorithms)[type]);
  
  return algorithm ? MAKE_DEFLATE(algorithm) : NULL;
}

static struct compress_instance *kex_make_inflate(struct object_list *algorithms,
						  int type)
{
  CAST_SUBTYPE(compress_algorithm, algorithm, LIST(algorithms)[type]);

  return algorithm ? MAKE_INFLATE(algorithm) : NULL;
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

static void
do_handle_newkeys(struct packet_handler *c,
		  struct ssh_connection *connection,
		  struct lsh_string *packet)
{
  CAST(newkeys_handler, closure, c);
  struct simple_buffer buffer;
  unsigned msg_number;

  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_NEWKEYS)
      && (parse_eod(&buffer)))
    {
      connection->rec_crypto = closure->crypto;
      connection->rec_mac = closure->mac;
      connection->rec_compress = closure->compression;

      connection->kex_state = KEX_STATE_INIT;

      connection->dispatch[SSH_MSG_NEWKEYS] = NULL;

      KILL(closure);
    }
  else
    PROTOCOL_ERROR(connection->e, "Invalid NEWKEYS message");
  lsh_string_free(packet);
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

struct make_kexinit *make_simple_kexinit(struct randomness *r,
					 struct int_list *kex_algorithms,
					 struct int_list *hostkey_algorithms,
					 struct int_list *crypto_algorithms,
					 struct int_list *mac_algorithms,
					 struct int_list *compression_algorithms,
					 struct int_list *languages)
{
  NEW(simple_kexinit, res);

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



/* GABA:
   (class
     (name install_new_keys)
     (super install_keys)
     (vars
       (is_server simple int)
       (algorithms object object_list)))
*/

static int do_install(struct install_keys *c,
		      struct ssh_connection *connection,
		      struct hash_instance *secret)
{
  CAST(install_new_keys, closure, c);
  struct crypto_instance *rec;
  struct crypto_instance *send;

  rec = kex_make_decrypt(secret, closure->algorithms,
			 KEX_ENCRYPTION_SERVER_TO_CLIENT ^ closure->is_server,
			 connection->session_id);
  if (!rec)
    /* Weak or invalid key */
    return 0;

  send = kex_make_encrypt(secret, closure->algorithms,
			  KEX_ENCRYPTION_CLIENT_TO_SERVER ^ closure->is_server,
			  connection->session_id);
  if (!send)
    {
      KILL(rec);
      return 0;
    }
  
  /* Keys for receiving */
  connection->dispatch[SSH_MSG_NEWKEYS] = make_newkeys_handler
    (rec,
     kex_make_mac(secret, closure->algorithms,
		  KEX_MAC_SERVER_TO_CLIENT ^ closure->is_server,
		  connection->session_id),
     kex_make_inflate(closure->algorithms,
		      KEX_COMPRESSION_SERVER_TO_CLIENT ^ closure->is_server));

  /* Keys for sending */
  /* NOTE: The NEWKEYS-message should have been sent before this
   * is done. */
  connection->send_crypto = send;
  
  connection->send_mac 
    = kex_make_mac(secret, closure->algorithms,
		   KEX_MAC_CLIENT_TO_SERVER ^ closure->is_server,
		   connection->session_id);

  connection->send_compress
    = kex_make_deflate(closure->algorithms,
		       KEX_COMPRESSION_CLIENT_TO_SERVER ^ closure->is_server);
  
  return 1;
}

struct install_keys *make_install_new_keys(int is_server,
					   struct object_list *algorithms)
{
  NEW(install_new_keys, self);

  self->super.install = do_install;
  self->is_server = is_server;
  self->algorithms = algorithms;

  return &self->super;
}

#if 0
struct keypair_info *make_keypair_info(struct lsh_string *public,
				       struct signer *private)
{
  NEW(keypair_info, self);
  
  self->public = public;
  self->private = private;
  return self;
}
#endif

/* Returns a hash instance for generating various session keys. NOTE:
 * This mechanism changed in the transport-05 draft. Before this, the
 * exchange hash was not included at this point. */
struct hash_instance *
kex_build_secret(struct hash_algorithm *H,
		 struct lsh_string *exchange_hash,
		 mpz_t K)
{
  struct hash_instance *hash = MAKE_HASH(H);
  struct lsh_string *s = ssh_format("%n", K);

  HASH_UPDATE(hash, s->length, s->data);
  lsh_string_free(s);
  
  HASH_UPDATE(hash, exchange_hash->length, exchange_hash->data);

  return hash;
}


