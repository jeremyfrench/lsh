/* transport.h
 *
 * ssh transport protocol, and supporting types
 */

#ifndef LSH_TRANSPORT_H_INCLUDED
#define LSH_TRANSPORT_H_INCLUDED

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Generic packet */
struct simple_packet
{
  UINT32 length;
  UINT8 data[1];
}

struct ssh_packet
{
  UINT32 packet_length;  /* In network byteorder */
  UINT8 padding_length;
  UINT8 data[1];  /* Includes payload and padding */
};

/* Allocation */

/* The memory allocation model is as follows:
 *
 * Packets are allocated when the are needed. They may be passed
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

/* Simple buffer */
struct simple_buffer
{
  UNIT32 capacity;
  UINT32 pos;
  UINT8 *data;
};

void simple_buffer_init(struct simple_buffer *buffer,
			UINT32 capacity, UINT8 *data);

/* Returns the number of octets that were actually written into the buffer */

UINT32 simple_buffer_write(struct simple_buffer *buffer,
			   UINT32 length, UINT32 *data);

UINT32 simple_buffer_avail(struct simple_buffer *buffer);

/* A packet processing function.
 *
 * Typically, real processors will extend this struct, with fields
 * such as the process parameters, next processor, output socket, etc.
 * */

typedef int (*raw_processor_function)(struct packet_processor *context,
				      struct simple_packet *packet);
struct packet_processor
{
  /* Returns some (so far unspecified) return code */
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

#endif /* LSH_TRANSPORT_H_INCLUDED */
