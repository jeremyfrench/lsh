/* send.c
 *
 * The sending end of the rsync algorithm. 
 *
 * $Id$ */

#include "rsync.h"

#include <assert.h>

#define HASH_SIZE 0x1000

struct rsync_node
{
  struct rsync_node *next;
  UINT32 index;
  UINT32 length;
  
  unsigned sum_a;
  unsigned sum_b;

  UINT8 sum_md5[MD5_DIGESTSIZE];
};

struct rsync_table
{
  struct rsync_node *hash[HASH_SIZE];
  UINT32 alloc_size;
  UINT32 size;

  struct rsync_node all_nodes[1];
};

static struct rsync_table *
make_rsync_table(UINT32 count, UINT32)
{
  unsigned i;
  
  struct rsync_table *table =
    malloc(sizeof(struct rsync_table) - sizeof(struct rsync_node)
	   + count * sizeof(rsync_node));
  
  if (!table)
    return NULL;

  for (i = 0; i<HASH_SIZE; i++)
    table->hash[i] = 0;

  table->alloc_size = count;
  table->size = 0;
}

struct rsync_node *
rsync_add_entry(struct rsync_table *table,
		UINT8 *input)
{
  struct rsync_node *node;
  unsigned h;
  
  assert(table->size < table->alloc_size);
  node = table->all_nodes + table->size;

  node->index = table->size++;

  /* NOTE: Length field is left uninitialized for now */
  
  node->sum_a = READ_UINT16(input);
  node->sum_b = READ_UINT16(input + 2);
  memcpy(node->sum_md5, input + 4, MD5_DIGESTSIZE);

  h = node->sum_a ^ node->sum_b;
  node->next = table->hash[h];
  table->hash[h] = node;

  return node;
}

int
rsync_read_table(struct rsync_read_table_state *s,
		 UINT32 length, UINT8 *input)
{
  while (length)
    if (!s->table)
      {
	UINT32 left = RSYNC_HEADER_SIZE - s->pos;
	if (length < left)
	  {
	    memcpy(s->buf + s->pos, input, length);
	    s->pos += length;
	    return RSYNC_PROGRESS;
	  }
	else
	  {
	    memcpy(s->buf + s->pos, input, left);
	    input += left;
	    length -= left;
	    s->pos = 0;
	    
	    s->count = READ_UINT32(s->buf);
	    s->block_size = READ_UINT32(s->buf + 4);
	    s->remainder = READ_UINT32(s->buf + 8);

	    if ( (s->count > s->max_count)
		 || (s->block_size > s->max_block_size)
		 || (s->remainder >= s->block_size))
	      return RSYNC_INPUT_ERROR;

	    s->table = make_rsync_table(s->count);

	    return (s->table) ? RSYNC_PROGRESS : RSYNC_MEMORY;
	  }
      }
    else
      {
	struct rsync_node *node;

	if (s->pos)
	  {
	    /* Do partial entries */
	    UINT32 left = RSYNC_ENTRY_SIZE - s->pos;
	    if (length < left)
	      {
		memcpy(s->buf + s->pos, input, length);
		s->pos += length;
		return RSYNC_PROGRESS;
	      }
	    else
	      {
		struct rsync_node *node;
		
		memcpy(s->buf + s->pos, input, left);
		input += left;
		length -= left;
		s->pos = 0;

		node = rsync_add_entry(s->table, s->buf);
	      }
	  }
	else if (length < RSYNC_ENTRY_SIZE)
	  {
	    /* New partial block */
	    memcpy(s->buf, input, length);
	    b->pos = length;
	    return RSYNC_PROGRESS;
	  }
	else
	  {
	    node = rsync_add_entry(s->table, input);
	    length -= RSYNC_ENTRY_SIZE;
	    input += RSYNC_ENTRY_SIZE;
	  }
	
	node->length = s->block_size;
	
	if (table->size == table->alloc_size)
	  {
	    if (s->remainder)
	      node->length = remainder;
	    
	    return length ? RSYNC_INPUT_ERROR : RSYNC_DONE;
	  }
      }
  return RSYNC_PROGRESS;
}

#define STATE_INITIAL 0
#define STATE_SEARCH 1
#define STATE_LITERAL 2

int rsync_send_init(struct rsync_send_state *s,
		    struct rsync_table *table)
{
  assert(table->block_size <= 0xffffffffU/2);
  s->buf_size = table->block_size * 2;
  s->table = table;

  s->buf = malloc(s->buf_size);
  
  if (!buf)
    return RSYNC_MEMORY;
  
  s->pos = 0;
  s->a_sum = s->b_sum = 0;
  s->state = STATE_SEARCH;
  
}

/* We first read s->buf_size octets into a buffer (we can improve this
 * if avail_in is large).
 *
 * When the buffer is full, we search for a match. If we find a match,
 * we output a literal and a match.
 *
 * If no match is found, we output a literal consisting of all but the
 * (block_size-1) last octets. */

int rsync_send(struct rsync_send_state *state, int flush)
{
  for (;;)
    switch (s->state)
      {
      case STATE_SEARCH:
	{
	  if (s->pos < s->table->block_size)
	    {
	      /* We have less than one block of data available */
	      UINT32 left = s->table_b - s->pos;
	      
	      if (s->avail_in < left)
		{
		  /* Copy some data and update sums */
		  rsync_update_1(&s->a_sum, &s->b_sum,
				 s->avail_in, s->next_in);
		  memcpy(s->buf + s->pos, s->next_in, s->avail_in);
		  s->pos += s->avail_in;
		  s->next_in += avail_in;
		  s->avail_in = 0;
		  return RSYNC_PROGRESS;
		}
	      else
		{
		  rsync_update_1(&s->a_sum, &s->b_sum,
				 left, s->next_in);
		  memcpy(s->buf + s->pos, s->next_in, left);
		  s->pos += left;
		  s->next_in += left;
		  s->avail_in -= left;
		}
	    }
	  assert(s->pos >= s->table->block_size);

	  /* Search */
	  {
	    UINT32 found;
	    struct rsync_node *n
	      = rsync_search(&s->a_sum, &s->b_sum, s->table->block_size,
			     MIN(s->table->block_size, avail_in),
			     s->buf + s->pos - s->table->block_size,
			     s->next_in, &found, self->table->hash);
	    if (n && (s->a_sum == n->a_sum) && (s->b_sum == node->b_sum))
	      {
		/* Block consisting of
		 *
		 * buf[pos - block_size + found ... pos], next_in[0 ... found]
		 *
		 * may match.
		 */

		struct md5_ctx m;
		struct UINT8 *digest[MD5_DIGESTSIZE];
		
		md5_init(&m);
		md5_update(&m, s->buf + s->pos + found - s->table->block_size,
			   s->table->block_size - found);
		md5_update(&m, found, s->next_in);
		md5_final(&m);
		md5_digest(&m, digest);

		if (!memcmp(n->md5, digest, MD5_DIGESTSIZE))
		  {
		    /* A match! */
		    ...
		  }
	      }
	  }
	}
      }
}
