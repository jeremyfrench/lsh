/* pad.h
 *
 * Processor for padding and formatting ssh-packets
 */

#ifndef LSH_PAD_H_INCLUDED
#define LSH_PAD_H_INCLUDED

#include "abstract_io.h"
#include "abstract_crypto.h"

/* Input to the processor is a packet with the payload. Output is a
 * packet containing a formatted ssh packet (with correct byte order,
 * etc). */
struct packet_pad
{
  struct abstract_write_pipe super;

  unsigned block_size; /* At least 8, even for stream ciphers */

  struct randomness *random;
  void *state;
};

struct abstract_write *
make_packet_pad(struct abstract_write *continuation,
		unsigned block_size,
		struct randomness *random);

#endif /* LSH_PAD_H_INCLUDED */
