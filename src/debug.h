/* debug.h
 *
 * Packet processor dumping packets to a file.
 */

#ifndef LSH_DEBUG_H_INCLUDED
#define LSH_DEBUG_H_INCLUDED

#include <stdio.h>
#include "transport.h"

struct debug_processor
{
  struct chained_processor c;
  FILE *output;
};

struct packet_processor *make_debug_processor(FILE *output,
					      struct packet_processor *continuation);


#endif */ LSH_DEBUG_H_INCLUDED */
