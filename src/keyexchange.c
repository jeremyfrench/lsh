/* keyexchange.c
 *
 */

#include "keyexchange.h"
#include "parse.h"

static int do_handle_kexinit(struct abstract_write **w,
			     struct lsh_string *packet)
{
  struct kexinit *msg = parse_kexinit(packet);

  if (!msg)
    return 0;

  lsh_free(packet);

  
  {
    
  
  }
}

#define NLISTS 10

struct kexinit * parse_kexinit(struct lsh_string *packet)
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

  res = xalloc(sizeof(keyexinit));

  if (!parse_string(&buffer, 16, &res->cookie))
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
  
  res->kex_algorithms = list[0];
  res->server_host_key_algorithms = lists[1];
  res->encryption_algorithms_client_to_server = list[2];
  res->encryption_algorithms_server_to_client = list[3];
  res->mac_algorithms_client_to_server = list[4];
  res->mac_algorithms_server_to_client = list[5];
  res->compression_algorithms_client_to_server = list[6];
  res->compression_algorithms_server_to_client = list[7];
  res->languages_client_to_server = list[8];
  res->languages_server_to_client = list[9];

  return res;
}
