/* keyexchange.c
 *
 *
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

struct kexinit_handler
{
  struct packet_handler super;
  int type;
  
  struct make_kexinit *init;
  
  /* Maps names to algorithms. It's dangerous to lookup random atoms
   * in this table, as not all objects have the same type. This
   * mapping is used only on atoms that have appeared in *both* the
   * client's and the server's list of algorithms (of a certain type),
   * and therefore the remote side can't screw things up. */

  struct alist *algorithms;

  struct ssh_service *finished;
};

#define NLISTS 10

static struct kexinit *parse_kexinit(struct lsh_string *packet)
{
  struct kexinit *res;
  struct simple_buffer buffer;
  struct simple_buffer sub_buffer;
  int msg_number;
  UINT32 reserved;
  
  int *lists[NLISTS];
  int i;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!parse_uint8(&buffer, &msg_number)
      || (msg_number != SSH_MSG_KEXINIT) )
    return 0;

  NEW(res);

  if (!parse_octets(&buffer, 16, res->cookie))
    {
      lsh_free(res);
      return NULL;
    }
  
  for (i = 0; i<NLISTS; i++)
    {
      if (!parse_sub_buffer(&buffer, &sub_buffer)
	  || ! (lists[i] = parse_atom_list(&sub_buffer)))
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
	lsh_free(lists[i]);
      lsh_free(res);
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
  

int initiate_keyexchange(struct ssh_connection *connection,
			 int type,
			 struct kexinit *kex,
			 struct lsh_string *first_packet)
{
  int res;
  struct lsh_string *s;
  
  kex->first_kex_packet_follows = !!first_packet;
  connection->kexinits[type] = kex;

  s = format_kex(kex);

  /* Save value for later signing */
  connection->literal_kexinits[type] = s; 

  res = A_WRITE(connection->write, lsh_string_dup(s));
  
  if (!LSH_CLOSEDP(res) && first_packet)
    return res | A_WRITE(connection->write, first_packet);
  else
    return res;
}

static int select_algorithm(int *server_list, int *client_list)
{
  /* FIXME: This quadratic complexity algorithm should do as long as
   * the lists are short. */
  int i, j;

  for(i = 0; client_list[i] >= 0; i++)
    {
      if (!client_list[i])
	/* Unknown algorithm */
	continue;
      for(j = 0; server_list[j] > 0; j++)
	if (client_list[i] == server_list[j])
	  return client_list[i];
    }

  return 0;
}

int disconnect_kex_failed(struct ssh_connection *connection, char *msg)
{
  return A_WRITE(connection->write,
		 format_disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
				   msg, ""));
}

static int do_handle_kexinit(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct kexinit_handler *closure = (struct kexinit_handler *) c;
  struct kexinit *msg = parse_kexinit(packet);

  int kex_algorithm;
  int hostkey_algorithm;

  int parameters[KEX_PARAMETERS];
  void **algorithms;

  int i;
  int res = 0;

  MDEBUG(closure);
  MDEBUG(msg);
  
  if (!msg)
    return LSH_FAIL | LSH_DIE;

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
      
      res = A_WRITE(connection->write, packet);
      if (LSH_CLOSEDP(res))
	return res;
    }

  /* Select key exchange algorithms */

  if (connection->kexinits[0]->kex_algorithms[0]
      == connection->kexinits[1]->kex_algorithms[0])
    {
      /* Use this algorithm */
      kex_algorithm = connection->kexinits[0]->kex_algorithms[0];
    }
  else
    {
      if (msg->first_kex_packet_follows)
	{
	  /* Wrong guess */
	  connection->kex_state = KEX_STATE_IGNORE;
	}
      /* FIXME: Ignores that some keyechange algorithms require
       * certain features of the host key algorithms. */
      
      kex_algorithm
	= select_algorithm(connection->kexinits[0]->kex_algorithms,
			   connection->kexinits[1]->kex_algorithms);

      if  (!kex_algorithm)
	{
	  disconnect_kex_failed(connection,
				"No common key exchange method.\r\n");
	  
	  return res | LSH_FAIL | LSH_CLOSE;
	}
    }
  hostkey_algorithm
    = select_algorithm(connection->kexinits[0]->server_hostkey_algorithms,
		       connection->kexinits[1]->server_hostkey_algorithms);
  
  for(i = 0; i<KEX_PARAMETERS; i++)
    {
      parameters[i]
	= select_algorithm(connection->kexinits[0]->parameters[i],
			   connection->kexinits[1]->parameters[i]);
      
      if (!parameters[i])
	{
	  disconnect_kex_failed(connection, "");
	  return res | LSH_FAIL | LSH_CLOSE;
	}
    }
  
  algorithms = lsh_space_alloc(KEX_PARAMETERS*sizeof(void *));
  
  for (i = 0; i<KEX_PARAMETERS; i++)
    algorithms[i] = ALIST_GET(closure->algorithms, parameters[i]);
      
  return res
    | KEYEXCHANGE_INIT( (struct keyexchange_algorithm *)
			ALIST_GET(closure->algorithms, kex_algorithm),
			connection,
			closure->finished,
			hostkey_algorithm,
			ALIST_GET(closure->algorithms, hostkey_algorithm),
			algorithms);
}

struct packet_handler *make_kexinit_handler(int type,
					    struct make_kexinit *init,
					    struct alist *algorithms,
					    struct ssh_service *finished)
{
  struct kexinit_handler *self;

  NEW(self);

  self->super.handler = do_handle_kexinit;

  self->type = type;
  self->init = init;
  self->algorithms = algorithms;
  self->finished = finished;
  
  return &self->super;
}

/* FIXME: THis function can't handle IV:s at all */
static struct lsh_string *kex_make_key(struct hash_instance *secret,
				       UINT32 key_length,
				       int type,
				       struct lsh_string *session_id)
{
  /* Indexed by the KEX_* values */
  static /* const */ char *tags = "CDEF";
  
  struct lsh_string *key;
  struct hash_instance *hash;
  UINT8 *digest;
  
  key = lsh_string_alloc(key_length);

  debug("Constructing session key of type %d\n", type);
  
  if (!key_length)
    return key;
  
  hash = HASH_COPY(secret);
  digest = alloca(hash->hash_size);

  HASH_UPDATE(hash, 1, tags + type); 
  HASH_UPDATE(hash, session_id->length, session_id->data);
  HASH_DIGEST(hash, digest);

  if (key_length > hash->hash_size)
    fatal("Not implemented\n");

  memcpy(key->data, digest, key_length);
  lsh_free(hash);

  debug_hex(key->length, key->data);
  return key;
}
  
struct crypto_instance *kex_make_encrypt(struct hash_instance *secret,
					 void **algorithms,
					 int type,
					 struct ssh_connection *connection)
{
  struct crypto_algorithm *algorithm = algorithms[type];
  struct lsh_string *key;
  struct crypto_instance *crypto;
  
  if (!algorithm)
    return NULL;

  key = kex_make_key(secret, algorithm->key_size,
					type, connection->session_id);
  /* FIXME: No IV. Note that for DES, instantiating the crypto can
   * fail, if the key happens to be weak. */

  crypto = MAKE_ENCRYPT(algorithm, key->data);

  lsh_string_free(key);
  return crypto;
}

struct crypto_instance *kex_make_decrypt(struct hash_instance *secret,
					 void **algorithms,
					 int type,
					 struct ssh_connection *connection)
{
  struct crypto_algorithm *algorithm = algorithms[type];
  struct lsh_string *key;
  struct crypto_instance *crypto;
  
  if (!algorithm)
    return NULL;
  
  key = kex_make_key(secret, algorithm->key_size,
		     type, connection->session_id);
  /* FIXME: No IV. Note that for DES, instantiating the crypto can
   * fail, if the key happens to be weak. */

  crypto = MAKE_DECRYPT(algorithm, key->data);

  lsh_string_free(key);
  return crypto;
}

struct mac_instance *kex_make_mac(struct hash_instance *secret,
				  void **algorithms,
				  int type,
				  struct ssh_connection *connection)
{
  struct mac_algorithm *algorithm = algorithms[type];
  struct mac_instance *mac;
  struct lsh_string *key;

  if (!algorithm)
    return NULL;

  key = kex_make_key(secret, algorithm->key_size,
		     type, connection->session_id);

  mac = MAKE_MAC(algorithm, key->data);

  lsh_string_free(key);
  return mac;
}

struct newkeys_handler
{
  struct packet_handler super;
  struct crypto_instance *crypto;
  struct mac_instance *mac;
};

static int do_handle_newkeys(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct newkeys_handler *closure = (struct newkeys_handler *) c;
  struct simple_buffer buffer;
  int msg_number;

  MDEBUG(closure);
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_NEWKEYS)
      && (parse_eod(&buffer)))
    {
      connection->rec_crypto = closure->crypto;
      connection->rec_mac = closure->mac;

      connection->kex_state = KEX_STATE_INIT;

      connection->dispatch[SSH_MSG_NEWKEYS] = NULL;

      lsh_free(closure);
      return LSH_OK | LSH_GOON;
    }
  else
    return LSH_FAIL | LSH_DIE;
}

struct packet_handler *
make_newkeys_handler(struct crypto_instance *crypto,
		     struct mac_instance *mac)
{
  struct newkeys_handler *self;

  NEW(self);

  self->super.handler = do_handle_newkeys;
  self->crypto = crypto;
  self->mac = mac;

  return &self->super;
}

struct test_kexinit
{
  struct make_kexinit super;
  struct randomness *r;
};

static struct kexinit *do_make_kexinit(struct make_kexinit *c)
{
  struct test_kexinit *closure = (struct test_kexinit *) c;
  struct kexinit *res;

  static int kex_algorithms[] = { ATOM_DIFFIE_HELLMAN_GROUP1_SHA1, -1 };
  static int server_hostkey_algorithms[] = { ATOM_SSH_DSS, -1 };
  static int crypto_algorithms[] = { ATOM_ARCFOUR, ATOM_NONE, -1 };
  static int mac_algorithms[] = { ATOM_HMAC_SHA1, -1 };
  static int compression_algorithms[] = { ATOM_NONE, -1 };
  static int languages[] = { -1 };

  MDEBUG(closure);

  NEW(res);
  
  RANDOM(closure->r, 16, res->cookie);
  res->kex_algorithms = kex_algorithms;
  res->server_hostkey_algorithms = server_hostkey_algorithms;
  res->parameters[KEX_ENCRYPTION_CLIENT_TO_SERVER] = crypto_algorithms;
  res->parameters[KEX_ENCRYPTION_SERVER_TO_CLIENT] = crypto_algorithms;
  res->parameters[KEX_MAC_CLIENT_TO_SERVER] = mac_algorithms;
  res->parameters[KEX_MAC_SERVER_TO_CLIENT] = mac_algorithms;
  res->parameters[KEX_COMPRESSION_CLIENT_TO_SERVER] = compression_algorithms;
  res->parameters[KEX_COMPRESSION_SERVER_TO_CLIENT] = compression_algorithms;
  res->languages_client_to_server = languages;
  res->languages_server_to_client = languages;
  res->first_kex_packet_follows = 0;

  return res;
}

struct make_kexinit *make_test_kexinit(struct randomness *r)
{
  struct test_kexinit *res;

  NEW(res);

  res->super.make = do_make_kexinit;
  res->r = r;

  return &res->super;
}
