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

/* Only records length and start pointer */
int parse_string(struct simple_buffer *buffer,
		 UINT32 *length, UINT8 **start);

/* Copies a given number of octets, without any length header */
int parse_octets(struct simple_buffer *buffer,
		 UINT32 length, UINT8 *start);

/* Copies a substring */
struct lsh_string *parse_string_copy(struct simple_buffer *buffer);

/* Initializes subbuffer to parse a string from buffer */
int parse_sub_buffer(struct simple_buffer *buffer,
		     struct simple_buffer *subbuffer);

int parse_uint8(struct simple_buffer *buffer, UINT8 *result);

int parse_boolean(struct simple_buffer *buffer, int *result);

int parse_bignum(struct simple_buffer *buffer, mpz_t result);

int parse_atom(struct simple_buffer *buffer, int *result);

/* Returns 1 on success, 0 on failure, and -1 at end of buffer.
 * Unknown atoms sets result to zero. */
int parse_next_atom(struct simple_buffer *buffer, int *result);

/* Allocates an array of integers. The 0 atom means an unknown atom
 * was read. The list is terminated with -1. Returns a NULL pointer on
 * error. */
int *parse_atom_list(struct simple_buffer *buffer);

/* Returns success (i.e. 1) iff there is no data left */
int parse_eod(struct simple_buffer *buffer);

#endif /* LSH_PARSE_H_INCLUDED */
