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

#include "abstract_io.h"
#include "connection.h"
#include "format.h"
#include "keyexchange.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "ssh.h"
#include "xalloc.h"

#define NLISTS 10

struct kexinit *parse_kexinit(struct lsh_string *packet)
{
  struct kexinit *res;
  struct simple_buffer buffer;
  struct simple_buffer sub_buffer;
  UINT8 msg_number;
  UINT32 reserved;
  
  int *lists[NLISTS];
  int i;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (!parse_uint8(&buffer, &msg_number)
      || (msg_number != SSH_MSG_KEXINIT) )
    return 0;

  res = xalloc(sizeof(struct kexinit));

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
  res->server_host_key_algorithms = lists[1];

  for (i=0; i<KEX_PARAMETERS; i++)
    res->parameters[i] = lists[2 + i];

  res->languages_client_to_server = lists[8];
  res->languages_server_to_client = lists[9];

  return res;
}

#if 0
struct abstract_write *make_packet_kexinit(struct handle_kexinit *handler)
{
  struct handle_kexinit_packet *closure
    = xalloc(sizeof(struct handle_kexinit_packet));

  closure->super.write = do_handle_kexinit;
  closure->handler = handler;

  return &closure->super;
}
#endif

struct lsh_string *format_kex(struct kexinit *kex)
{
  return ssh_format("%c%ls%A%A%A%A%A%A%A%A%A%A%c%i",
		    SSH_MSG_KEXINIT,
		    16, kex->cookie,
		    kex->kex_algorithms,
		    kex->server_host_key_algorithms,
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
			 struct kexinit *kex,
			 struct lsh_string *first_packet)
{
  int res;
  lsh_string *s;
  
  kex->first_kex_packet_follows = !!first_packet;
  connection->kexinits[connection->type] = kex;

  s = format_kex(kex);

  /* Save value for later signing */
  connection->literal_kexinits[connection->type] = s; 

  res = A_WRITE(connection->write, lsh_string_dup(s));
  
  if ( (res == WRITE_OK) && first_packet)
    return A_WRITE(connection->write, first_packet);
  else
    return res;
}

int select_algorithm(int *server_list, int *client_list)
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
	if (client_list[i] = server_list[j])
	  return client_list[i];
    }

  return 0;
}

int send_disconnect(struct ssh_conection, char *msg)
{
  return A_WRITE(connection->write,
		 ssh_format("%c%i%z%z",
			    SSH_MSG_DISCONNECT,
			    SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
			    msg, ""));
}

static int do_handle_kexinit(struct packet_hander *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  struct handle_kexinit *closure = (struct handle_kexinit_packet *) c;
  struct kexinit *msg = parse_kexinit(packet);

  int kex_algorithm;
  int hostkey_algorithm;

  int parameters[KEX_PARAMETERS];
  void **algorithms;

  struct packet_handler newkeys;

  int i;
  
  if (!msg)
    return 0;

  /* Save value for later signing */
  connection->literal_kexinits[connection->type] = packet;
  
  connection->kexinits[!connection->type] = msg;
  
  /* Have we sent a kexinit message? */
  if (!connection->kexinits[connection->type])
    {
      int res;
      struct kexinit *sent =  GENERATE_KEXINIT(closure->init);
      connection->kexinits[connection->type] = sent;
      res = A_WRITE(connection->write, format_kex(sent));
      if (res != WRITE_OK)
	return res;
    }

  /* Select key exchange algorithms */

  if (connection->kexinits[0]->kex_algorithms[0]
      == connection->kexinits[1]->kex_algorithms[1])
    {
      /* Use this algorithm */
      kex_algorithm = connection->sent_kexinit->kex_algorithms[0];
    }
  else
    {
      if (msg->first_kex_packet_follows)
	{
	  /* Wrong guess */
	  connection->ignore_one_packet = 1;
	}
      /* FIXME: Ignores that some keyechange algorithms require
       * certain features of the host key algorithms. */
      
      kex_algorithm = select_algorithm(connection->kexinits[0]->kex_algorithm,
				       connection->kexinits[1]->kex_algorithm);
      if  (!kex_algorithm)
	{
	  send_disconnect(connection, "No common key exchange method.\r\n");

	  /* FIXME: We want the disconnect message to be sent
	   * before the socket is closed. How? */
	  return WRITE_CLOSED;
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
	      send_disconnect(connection, "");
	      return wRITE_CLOSED;
	    }
	}

      algorithms = xalloc(KEX_PARAMETERS*sizeof(void *));

      for (i = 0; i<KEX_PARAMETERS; i++)
	algorithms[i] = ALIST_GET(closure->algorithms, parameters[i]);
      
      newkeys = make_newkeys_handler(ALIST_GET(closure->algorithms,
					       hostkey_algorithm),
				     algorithms);

      return KEYEXCHANGE_INIT(ALIST_GET(algorithms, kex_algorithm), connection);
    }
}

static int do_handle_newkeys(struct packet_handler *c,
			     struct ssh_connection *connection,
			     struct lsh_string *packet)
{
  
struct packet_handler *
make_newkeys_handler(struct signature_algorithm *hostkey_algorithm,
		     void *parameters)
{
  

  
