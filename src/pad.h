/* pad.h
 *
 * Processor for padding and formatting ssh-packets
 */

#ifndef LSH_PAD_H_INCLUDED
#define LSH_PAD_H_INCLUDED

#include "transport.h"

typedef void (*random_function)(void *state, UINT32 length, UINT8 *dst);

/* Input to the processor is a packet with the payload. Output is a
 * packet containing a formatted ssh packet (with correct byte order,
 * etc). */
struct packet_pad
{
  struct abstract_write_pipe c;

  unsigned block_size; /* At least 8, even for stream ciphers */

  random_function random;
  void *state;
};

struct abstract_write *
make_pad_processor(struct abstract_write *continuation,
		   unsigned block_size,
		   random_function random,
		   void *state);

#if 0
/* Input to the processor is a packet with the payload. Output is a
 * packet containing a formatted ssh packet (with correct byte order,
 * etc). No padding is done. */
struct format_processor
{
  struct abstract_write_pipe c;
};

struct abstract_write *make_packet_pad(abstract_write *continuation);
#endif


#endif /* LSH_PAD_H_INCLUDED */
