/* read_packet.h
 *
 * Read-handler to read a packet at a time.
 */

#ifndef LSH_READ_PACKET_H_INCLUDED
#define LSH_READ_PACKET_H_INCLUDED

#include "abstract_io.h"
#include "abstract_crypto.h"

struct read_packet
{
  struct read_handler super; /* Super type */

  int state;
  UINT32 max_packet;

  UINT32 sequence_number; /* Attached to read packets */
  
  /* Buffer partial headers and packets. */
  UINT32 pos;
  struct lsh_string *buffer;
  UINT32 crypt_pos;
  
  struct mac_instance *mac;
  struct crypto_instance *crypto;

  UINT8 *computed_mac; /* Must point to an area large enough to hold a mac */
  
  struct abstract_write *handler;
};

struct read_handler *make_read_packet(struct abstract_write *handler,
				      UINT32 max_packet);

#endif /* LSH_READ_PACKET_H_INCLUDED */
