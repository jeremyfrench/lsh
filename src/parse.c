/* parse.c
 *
 */

#include "parse.h"

void simple_buffer_init(struct simple_buffer *buffer,
			UINT32 capacity, UINT8 *data)
{
  buffer->capacity = capacity;
  buffer->pos = 0;
  buffer->data = data;
}

#define BUFFER_LEFT (buffer->capacity - buffer->pos)
#define HERE (buffer->data + buffer->pos)
#define ADVANCE(n) (buffer->pos  += (n))

int parse_uint32(struct simple_buffer *buffer, UINT32 *result)
{
  if (BUFFER_LEFT < 4)
    return 0;

  *result = READ_INT32(HERE);
  ADVANCE(4);
  return 1;
}

int parse_string(struct simple_buffer *buffer,
		 UINT32 *length, UINT8 **start)
{
  UINT32 l;

  if (!parse_uint32(buffer, &l))
    return 0;

  if (BUFFER_LEFT < length)
    return 0;

  *length = l;
  *start = HERE;
  ADVANCE(l);
}

/* Initializes subbuffer to parse a string from buffer */
int parse_sub_buffer(struct simple_buffer *buffer,
		     struct simple_buffer *subbuffer)
{
  UINT32 length;
  UINT8 *data;

  if (!parse_string(buffer, &length, &data))
    return 0;

  simple_buffer_init(subbuffer, length, data);
  return 1;
}

int parse_uint8(struct simple_buffer *buffer, uint8 *result)
{
  if (!LEFT)
    return 0;

  *result = HERE[0];
  ADVANCE(1);
  return 1;
}

int parse_bignum(struct simple_buffer *buffer, mpz_t result)
{
  UINT32 length;
  UINT8 *digits;

  if (!parse_string(buffer, &length, &data))
    return 0;

  /* init mpz */
#error
}

/* Returns 1 on success, 0 on failure, and -1 at end of buffer.
 * Unknown atoms sets result to zero. */

/* NOTE: This functions record the fact that it has read to the end of
 * the buffer by setting the position to *beyond* the end of the
 * buffer. */
int parse_next_atom(struct simple_buffer *buffer, int *result)
{
  UINT32 i;

  if (buffer->pos > buffer->capacity)
    return -1;

  for(i = 0; i < left; i++)
    if (HERE[i] == ',')
      {
	*result = lookup_atom(HERE, i);
	ADVANCE[i+1];
	return 1;
      }

  *result = lookup(HERE, i);
  ADVANCE(i+1);  /* Beyond end of buffer */
  return 1;
}

/* Returns success (i.e. 1) iff there is no data left */
int parse_eod(struct simple_buffer *buffer);
{
  return !LEFT;
}
