/* keyexchange.h
 *
 */

#ifndef LSH_KEYEXCHANGE_H_INCLUDED
#define LSH_KEYEXCHANGE_H_INCLUDED

struct kexinit
{
  UINT8 cookie[16];
  /* Zero terminated list of atoms */
  int *kex_algorithms; 
  int *server_host_key_algorithms;
  int *encryption_algorithms_client_to_server;
  int *encryption_algorithms_server_to_client;
  int *mac_algorithms_client_to_server;
  int *mac_algorithms_server_to_client;
  int *compression_algorithms_client_to_server;
  int *compression_algorithms_server_to_client;
  int *languages_client_to_server;
  int *languages_server_to_client;
  int first_kex_packet_follows;
}
    
struct handle_kexinit
{
  struct abstract_write super;
};

struct server_keyexchange
{
  struct abstract_write p;
};


#endif /* LSH_KEYEXCHANGE_H_INCLUDED */
