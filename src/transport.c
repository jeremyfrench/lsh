/* transport.c
 *
 */

#include "transport.h"
#include "xalloc.h"

struct simple_packet *simple_packet_alloc(UINT32 length)
{
  struct simple_packet *packet
    = xalloc(sizeof(struct simple_packet) - 1 + length);
  packet->length = length;
  return packet;
}

void simple_packet_free(struct simple_packet *packet)
{
  free(packet);
}

#if 0
void simple_buffer_init(struct simple_buffer *buffer,
			UINT32 capacity, UINT8 *data)
{
  buffer->capacity = capacity;
  buffer->pos = 0;
  buffer->data = data;
}

UINT32 simple_buffer_write(struct simple_buffer *buffer,
			   UINT32 length, UINT32 *data)
{
  UINT32 left = buffer->capacity - buffer->pos;
  UINT32 copy = MIN(left, length);
  
  memcpy(buffer->data + buffer->pos, data, copy);
  return copy;
}

UINT32 simple_buffer_avail(struct simple_buffer *buffer)
{
  return buffer->capacity - buffer->pos;
}
#endif

int apply_processor(struct packet_processor *closure,
		    struct simple_packet *packet)
{
  return closure->f(closure, packet);
}
