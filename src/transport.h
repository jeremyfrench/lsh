/* transport.h
 *
 * ssh transport protocol, and supporting types
 */

#ifndef LSH_TRANSPORT_H_INCLUDED
#define LSH_TRANSPORT_H_INCLUDED

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Reads a 32-bit integer, in network byte order */
#define READ_UINT32(p)				\
((((UINT32) (p)[0]) << 24)			\
 | (((UINT32) (p)[0]) << 16)			\
 | (((UINT32) (p)[0]) << 8)			\
 | ((UINT32) (p)[0]))

#define WRITE_UINT32(p, i)			\
do {						\
  (p)[0] = ((i) >> 24) & 0xff;			\
  (p)[0] = ((i) >> 16) & 0xff;			\
  (p)[0] = ((i) >> 8) & 0xff;			\
  (p)[0] = (i) & 0xff;				\
} while(0)

/* Generic packet */
struct simple_packet
{
  UINT32 length;
  UINT8 data[1];
}

#if 0
struct ssh_packet
{
  UINT32 packet_length;  /* In network byteorder */
  UINT8 padding_length;
  UINT8 data[1];  /* Includes payload and padding */
};
#endif

/* Allocation */

/* The memory allocation model is as follows:
 *
 * Packets are allocated when the are needed. A packet may be passed
 * through a chain of processing functions, until it is finally
 * discarded or transmitted, at which time it is deallocated.
 * Processing functions may deallocate their input packets and
 * allocate fresh packets to pass on; therefore, any data from a
 * packet that is needed later must be copied into some other storage.
 *
 * At any time, each packet is own by a a particular processing
 * function. Pointers into a packet are valid only while you own it.
 * */

/* Size is the maximum amount of payload + padding that will be stored
 * in the packet. */

struct simple_packet *simple_packet_alloc(UINT32 size);
void simple_packet_free(struct simple_packet *packet);

/* A packet processing function.
 *
 * Typically, real processors will extend this struct, with fields
 * such as the process parameters, next processor, output socket, etc.
 * */

/* This function returns 0 if there's some fatal protocol error
 * (implying immediate shutdown of (this direction of) a connection.
 * Otherwise returns 1. */
typedef int (*raw_processor_function)(struct packet_processor *context,
				      struct simple_packet *packet);
struct packet_processor
{
  raw_processor_function f;
};

int apply_processor(struct packet_processor *closure,
		    struct simple_packet *packet);

/* A processor that passes its result on to another processor */
struct chained_processor
{
  struct packet_processor p;
  struct *packet_processor *next;
};


/* error codes, returned from packet processors. zero means ok,
 * negative means a fatal protocol failure, and positive values are
 * errors that should be reported to the otrher end. */

#define LSH_ERR_TOO_LARGE_PACKET -1
#define LSH_ERR_BAD_LENGTH -2
#define LSH_ERR_BAD_MAC -3

#endif /* LSH_TRANSPORT_H_INCLUDED */
