/* void.h
 *
 * A packet processor that destroys all packets.
 */

#ifndef LSH_VOID_H_INCLUDED
#define LSH_VOID_H_INCLUDED

#include "transport.h"

struct abstract_write *make_packet_void();

#endif /* LSH_VOID_H_INCLUDED */
