/* void.h
 *
 * A packet processor that destroys all packets.
 */

#ifndef LSH_VOID_H_INCLUDED
#define LSH_VOID_H_INCLUDED

#include "transport.h"

struct void_processor
{
  struct packet_processor p;
};

struct packet_processor *make_void_processor();

#endif /* LSH_VOID_H_INCLUDED */
