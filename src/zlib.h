/* zlib.h
 *
 * Processor to compress packets using zlib
 */

#ifndef LSH_ZLIB_H_INCLUDED
#define LSH_ZLIB_H_INCLUDED

/* The input to the compressor should be a packet with payload only. */
struct zlib_processor
{
  struct abstract_write_pipe c;
  z_stream state;
}

struct packet_processor *make_zlib_processor(packet_processor *continuation,
					     level);

#endif /* LSH_ZLIB_H_INCLUDED */
