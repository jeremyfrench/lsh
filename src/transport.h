/* transport.h
 *
 * ssh transport protocol, and supporting types
 */

#ifndef LSH_TRANSPORT_H_INCLUDED
#define LSH_TRANSPORT_H_INCLUDED

#include "lsh_types.h"

#if 0
struct ssh_packet
{
  UINT32 packet_length;  /* In network byteorder */
  UINT8 padding_length;
  UINT8 data[1];  /* Includes payload and padding */
};
#endif

#if 0
/* error codes, returned from packet processors. zero means ok,
 * negative means a fatal protocol failure, and positive values are
 * errors that should be reported to the otrher end. */

#define LSH_ERR_TOO_LARGE_PACKET -1
#define LSH_ERR_BAD_LENGTH -2
#define LSH_ERR_BAD_MAC -3
#endif

#endif /* LSH_TRANSPORT_H_INCLUDED */
