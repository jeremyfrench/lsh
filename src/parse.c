/* parse.c
 *
 */

#include "parse.h"
#include "xalloc.h"

void simple_buffer_init(struct simple_buffer *buffer,
			UINT32 capacity, UINT8 *data)
{
  buffer->capacity = capacity;
  buffer->pos = 0;
  buffer->data = data;
}

#define LEFT (buffer->capacity - buffer->pos)
#define HERE (buffer->data + buffer->pos)
#define ADVANCE(n) (buffer->pos  += (n))

int parse_uint32(struct simple_buffer *buffer, UINT32 *result)
{
  if (LEFT < 4)
    return 0;

  *result = READ_UINT32(HERE);
  ADVANCE(4);
  return 1;
}

int parse_string(struct simple_buffer *buffer,
		 UINT32 *length, UINT8 **start)
{
  UINT32 l;

  if (!parse_uint32(buffer, &l))
    return 0;

  if (LEFT < l)
    return 0;

  *length = l;
  *start = HERE;
  ADVANCE(l);
  return 1;
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

int parse_uint8(struct simple_buffer *buffer, UINT8 *result)
{
  if (!LEFT)
    return 0;

  *result = HERE[0];
  ADVANCE(1);
  return 1;
}

int parse_boolean(struct simple_buffer *buffer, int *result)
{
  if (!LEFT)
    return 0;
  *result = HERE[0];
  ADVANCE(1);
  return 1;
}

int parse_bignum(struct simple_buffer *buffer, bignum result)
{
  UINT32 length;
  UINT8 *digits;

  if (!parse_string(buffer, &length, &digits))
    return 0;

  bignum_parse(result, length, digits);

  return 1;
}

int parse_atom(struct simple_buffer *buffer, int *result)
{
  UINT32 length;
  UINT8 *start;

  if ( (!parse_string(buffer, &length, &start))
       || length > 64)
    return 0;

  *result = lookup_atom(data, start);

  return 1;
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

  for(i = 0; i < LEFT; i++)
    {
      if (HERE[i] == ',')
	break;
      if (i == 64)
	/* Atoms can be no larger than 64 characters */
	return 0;
    }
  
  *result = lookup_atom(HERE, i);
  ADVANCE(i+1);  /* If the atom was terminated at the end of the
		  * buffer, rather than by a comma, this points beyond
		  * the end of the buffer */
  return 1;
}

int *parse_atom_list(struct simple_buffer *buffer)
{
  int count;
  int i;
  int *res;
  
  /* Count commas (no commas means one atom) */
  for (i = buffer->pos, count = 1; i < buffer->capacity; i++)
    if (buffer->data[i] == ',')
      count++;

  res = xalloc(sizeof(int) * (count+1));

  for (i = 0; i < count; i++)
    {
      switch(parse_next_atom(buffer, res+i))
	{
	case 1:
	  continue;
	case 0:
	  lsh_free(res);
	  return NULL;
	default:
	  fatal("Internal error\n");
	}
    }
  res[i] = -1;
  return res;
}

/* Returns success (i.e. 1) iff there is no data left */
int parse_eod(struct simple_buffer *buffer)
{
  return !LEFT;
}
