/* parse.h
 *
 * Parses the data formats used in ssh packets.
 */

#ifndef LSH_PARSE_H_INCLUDED
#define LSH_PARSE_H_INCLUDED

#include "atoms.h"
#include "bignum.h"

/* Simple buffer */
struct simple_buffer
{
  UINT32 capacity;
  UINT32 pos;
  UINT8 *data;
};

void simple_buffer_init(struct simple_buffer *buffer,
			UINT32 capacity, UINT8 *data);

/* Returns 1 on success, 0 on failure */
int parse_uint32(struct simple_buffer *buffer, UINT32 *result);
int parse_string(struct simple_buffer *buffer,
		 UINT32 *length, UINT8 **start);
/* Initializes subbuffer to parse a string from buffer */
int parse_sub_buffer(struct simple_buffer *buffer,
		     struct simple_buffer *subbuffer);
int parse_uint8(struct simple_buffer *buffer, UINT8 *result);
#define parse_boolean parse_uint8

int parse_bignum(struct simple_buffer *buffer, bignum *result);

/* Returns 1 on success, 0 on failure, and -1 at end of buffer.
 * Unknown atoms sets result to zero. */
int parse_next_atom(struct simple_buffer *buffer, int *result);

/* Returns success (i.e. 1) iff there is no data left */
int parse_eod(struct simple_buffer *buffer);

#if 0
/* Returns the number of octets that were actually written into the buffer */

UINT32 simple_buffer_write(struct simple_buffer *buffer,
			   UINT32 length, UINT32 *data);

UINT32 simple_buffer_avail(struct simple_buffer *buffer);
#endif

#endif /* LSH_PARSE_H_INCLUDED */
