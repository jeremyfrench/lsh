/* keyexchange.c
 *
 */

#include "abstract_io.h"
#include "connection.h"
#include "format.h"
#include "keyexchange.h"
#include "parse.h"
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
  res->encryption_algorithms_client_to_server = lists[2];
  res->encryption_algorithms_server_to_client = lists[3];
  res->mac_algorithms_client_to_server = lists[4];
  res->mac_algorithms_server_to_client = lists[5];
  res->compression_algorithms_client_to_server = lists[6];
  res->compression_algorithms_server_to_client = lists[7];
  res->languages_client_to_server = lists[8];
  res->languages_server_to_client = lists[9];

  return res;
}

static int do_handle_kexinit(struct abstract_write **w,
			     struct lsh_string *packet)
{
  struct handle_kexinit_packet *closure = (struct handle_kexinit_packet *) *w;
  struct kexinit *msg = parse_kexinit(packet);

  if (!msg)
    return 0;

  lsh_free(packet);

  return HANDLE_KEXINIT(closure->handler, msg);
}

struct abstract_write *make_packet_kexinit(struct handle_kexinit *handler)
{
  struct handle_kexinit_packet *closure
    = xalloc(sizeof(struct handle_kexinit_packet));

  closure->super.write = do_handle_kexinit;
  closure->handler = handler;

  return &closure->super;
}

struct lsh_string *format_kex(struct kexinit *kex)
{
  return ssh_format("%c%ls%A%A%A%A%A%A%A%A%A%A%c%i",
		    SSH_MSG_KEXINIT,
		    16, kex->cookie,
		    kex->kex_algorithms,
		    kex->server_host_key_algorithms,
		    kex->encryption_algorithms_client_to_server,
		    kex->encryption_algorithms_server_to_client,
		    kex->mac_algorithms_client_to_server,
		    kex->mac_algorithms_server_to_client,
		    kex->compression_algorithms_client_to_server,
		    kex->compression_algorithms_server_to_client,
		    kex->languages_client_to_server,
		    kex->languages_server_to_client,
		    kex->first_kex_packet_follows, 0);
}
  

int initiate_keyexchange(struct ssh_connection *connection,
			 struct kexinit *kex,
			 struct lsh_string *first_packet)
{
  int res;
  
  connection->sent_kexinit = kex;
  kex->first_kex_packet_follows = !!first_packet;
   
  res = A_WRITE(connection->write, format_kex(kex));

  if (res && first_packet)
    return A_WRITE(connection->write, first_packet);
  else
    return res;
}

    
