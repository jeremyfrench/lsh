/* decrypt.h
 *
 */

#ifndef LSH_DECRYPT_H_INCLUDED
#define LSH_DECRYPT_H_INCLUDED

#include "transport.h"
#include "crypto_common.h"

/* The input packets to this processor are arbitrary octet strings,
 * for instance as returned by read(). The data is collected,
 * decrypted, and the (padded) payload is passed on to the next packet
 * processor, as soon as a complete packet has been read. */
struct decrypt_processor
{
  struct chained_processor c;

  int state;
  UINT32 pos;

  UINT32 max_packet;
  
  struct simple_packet *recieved;

  unsigned mac_size;

  transform_function mac_function;
  void *mac_state;

  unsigned block_size;
  
  transform_function decrypt_function;
  void *decrypt_state;

  UINT8 block_buffer[1];
};

struct packet_processor *
make_decrypt_processor(struct packet_processor *containing,
		       UINT32 max_packet,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       unsigned block_size,
		       transform_function encrypt_function,
		       void *encrypt_state);



#endif /* LSH_DECRYPT_H_INCLUDED */
