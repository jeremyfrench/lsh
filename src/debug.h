/* debug.h
 *
 * Packet processor dumping packets to a file.
 */

#ifndef LSH_DEBUG_H_INCLUDED
#define LSH_DEBUG_H_INCLUDED

#include <stdio.h>
#include "abstract_io.h"

struct packet_debug
{
  struct abstract_write_pipe super;
  FILE *output;
};

struct abstract_write *
make_packet_debug(struct abstract_write *continuation, FILE *output);


#endif */ LSH_DEBUG_H_INCLUDED */
