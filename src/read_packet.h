/* read_packet.h
 *
 * Read-handler to read a packet at a time.
 */

#ifndef LSH_READ_PACKET_H_INCLUDED
#define LSH_READ_PACKET_H_INCLUDED

struct read_packet
{
  struct read_handler super; /* Super type */

  int state;
  UINT32 max_packet;

  /* Buffer partial headers and packets. */
  UINT32 pos;
  struct lsh_string *buffer;

  struct mac_instance;
  struct crypto_instance;
};

#endif /* LSH_READ_PACKET_H_INCLUDED */
