/* unpad.h
 *
 * Processor for unpadding and formatting ssh-packets
 */

#ifndef LSH_UNPAD_H_INCLUDED
#define LSH_UNPAD_H_INCLUDED

#include "transport.h"

/* Input to the processor is a padded payload. */
struct unpad_processor
{
  struct chained_processor c;
};

struct packet_processor *
make_unpad_processor(struct packet_processor *continuation);

#endif /* LSH_UNPAD_H_INCLUDED */
