/* write_buffer.h
 *
 */

#ifndef LSH_WRITE_BUFFER_H_INCLUDED
#define LSH_WRITE_BUFFER_H_INCLUDED

#include "abstract_io.h"

/* For the packet queue */
struct node
{
  struct node *next;
  struct node *prev;
  struct lsh_string *packet;
};

struct write_buffer
{
  struct abstract_write super;
  
  UINT32 block_size;

  int empty;
  
#if 0
  int try_write;
#endif
  
  struct node *head;
  struct node *tail;

  UINT32 pos; /* Partial packet */
  struct lsh_string *partial;

  UINT32 start;
  UINT32 end;
  UINT8 buffer[1]; /* Real size is twice the blocksize */
};

#if 0
struct write_callback
{
  struct callback c;
  struct write_buffer buffer;
};
#endif

struct write_buffer *write_buffer_alloc(UINT32 size);
int write_buffer_pre_write(struct write_buffer *buffer);

#endif /* LSH_WRITE_BUFFER_H_INCLUDED */
