/* write_buffer.c
 *
 */

#include "xalloc.h"

static int do_write(struct write_buffer *closure,
		    struct lsh_string *packet)
{
  struct node *new;
  if (!packet->length)
    {
      lsh_string_free(packet);
      return;
    }

  /* Enqueue packet */
  new = xalloc(sizeof(struct node));
  new->next = 0;
  
  if (closure->tail)
    {
      new->prev = closure->tail;
      closure->tail->next = new;
    }
  else
    {
      new->prev = NULL;
      closure->head = new;
    }
  closure->tail = new;

#if 0
  if (closure->try_write)
    {
      /* Attempt writing to the corresponding fd. */
    }
#endif

  return 1;
}

/* Copy data as necessary, before writing.
 *
 * FIXME: Writing of large packets could probably be optimized by
 * avoiding copying it into the buffer. */
void write_buffer_pre_write(struct write_buffer *buffer)
{
  UINT32 length = buffer->end - buffer->start;

  if (buffer->start > buffer->block_size)
    {
      /* Copy contents to the start of the buffer */
      memcpy(buffer->data, buffer->data + buffer->start, length);
      buffer->start = 0;
      buffer->end = length;
    }

  while (length < buffer->block_size)
    {
      /* Copy more data into buffer */
      if (buffer->partial)
	{
	  UINT32 partial_left = buffer->partial->length - buffer->pos;
	  UINT32 buffer_left = 2*buffer->block_size - length;
	  if (partial_left <= buffer_left)
	    {
	      /* The rest of the partial packet fits in the buffer */
	      memcpy(buffer->data + length,
		     buffer->partial->data + buffer->pos,
		     partial_left);

	      buffer->end += partial_left;
	      length += partial_left;
	      
	      lsh_string_free(buffer->partial);
	      buffer->partial = NULL;
	    }
	  else
	    {
	      memcpy(buffer->data + length,
		     buffer->partial->data + buffer->pos,
		     buffer_left);

	      buffer->end += buffer_left;
	      length += buffer_left;
	      buffer->pos += buffer_left;
	    }
	}
      else
	{
	  /* Dequeue a packet, if possible */
	  struct node *n = buffer->head;
	  if (n)
	    {
	      buffer->partial = n->packet;
	      buffer->pos = 0;
	      buffer->head = n->next;
	      if (buffer->head)
		buffer->head->->next = 0;
	      else
		buffer->tail = 0;
	    }
	  else
	    break;
	}
    }
  buffer->empty = !length;
}

struct write_buffer *write_buffer_alloc(UINT32 size)
{
  struct write_buffer *res = xalloc(sizeof(write_callback) - 1 + size*2);
  
  res->a.write = (abstract_write_f) do_write;
  
  res->block_size = size;

  res->empty = 1;

#if 0
  res->try_write = try; 
#endif
  
  res->head = res->tail = 0;

  res->pos = 0;
  res->packet = NULL;

  res->start = res->end = 0;

  return res;
}
