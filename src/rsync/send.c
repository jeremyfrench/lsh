/* send.c
 *
 * The sending end of the rsync algorithm. 
 *
 * $Id$ */

#include "rsync.h"

#include <assert.h>
#include <string.h>

#define HASH_SIZE 0x10000
#define HASH_SUM(a, b) (((a) ^ (b)) & 0xffff)
#define COMBINE_SUM(a, b) ((a) | ((b) << 16))

struct rsync_node
{
  struct rsync_node *next;
  UINT32 index;
  UINT32 length;
  
  UINT32 sum_weak; /* a | b << 16*/

  UINT8 sum_md5[MD5_DIGESTSIZE];
};

struct rsync_table
{
  struct rsync_node *hash[HASH_SIZE];
  UINT32 alloc_size;
  UINT32 size;
  UINT32 block_size;

  struct rsync_node all_nodes[1];
};

static struct rsync_table *
make_rsync_table(UINT32 count, UINT32 block_size)
{
  unsigned i;
  
  struct rsync_table *table =
    malloc(sizeof(struct rsync_table) - sizeof(struct rsync_node)
	   + count * sizeof(struct rsync_node));
  
  if (!table)
    return NULL;

  for (i = 0; i<HASH_SIZE; i++)
    table->hash[i] = NULL;

  table->alloc_size = count;
  table->size = 0;

  table->block_size = block_size;

  return table;
}

static struct rsync_node *
rsync_add_entry(struct rsync_table *table,
		UINT8 *input)
{
  struct rsync_node *node;
  unsigned a, b;
  unsigned h;

  assert(table->size < table->alloc_size);
  node = table->all_nodes + table->size;

  node->index = table->size++;

  /* NOTE: Length field is left uninitialized for now */
  
  a = READ_UINT16(input);
  b = READ_UINT16(input + 2);

  node->sum_weak = COMBINE_SUM(a, b);
  memcpy(node->sum_md5, input + 4, RSYNC_SUM_LENGTH);

  h = HASH_SUM(a, b);
  node->next = table->hash[h];
  table->hash[h] = node;

  return node;
}

static struct rsync_node *
rsync_lookup_1(struct rsync_node *n, UINT32 weak)
{
  while (n && (n->sum_weak != weak))
    n = n->next;

  return n;
}

static struct rsync_node *
rsync_lookup_2(struct rsync_node *n, UINT32 weak,
	       const UINT8 *digest)
{
  /* FIXME: This could be speeded up slightly if the hash lists were
   * kept sorted on weak_sum. */
  while (n && ( (n->sum_weak != weak)
		|| memcmp(n->sum_md5, digest, RSYNC_SUM_LENGTH)))
      n = n->next;

  return n;
}

static struct rsync_node *
rsync_lookup_block(struct rsync_send_state *s,
		   UINT32 start, UINT32 size)

{
  struct rsync_node *n;
  
  assert(size);

  if (size == s->table->block_size)
    {
      n = s->table->hash[HASH_SUM(s->sum_a, s->sum_b)];
      if (n)
	{
	  /* The first block might match. */
	  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);
	  struct md5_ctx m;
	  UINT8 digest[MD5_DIGESTSIZE];

	  /* First check our guess. */
	  if (s->guess && (s->guess->sum_weak == weak))
	    {
	      md5_init(&m);
	      md5_update(&m, s->buf + start, s->table->block_size);
	      md5_final(&m);
	      md5_digest(&m, digest);

	      if (!memcmp(s->guess->sum_md5, digest, RSYNC_SUM_LENGTH))
		{
		  /* Correct guess! */
		  n = s->guess;
		}
	      else
		n = rsync_lookup_2(n, weak, digest);
	    }
	  else
	    {
	      n = rsync_lookup_1(n, weak);
	      if (n)
		{
		  md5_init(&m);
		  md5_update(&m, s->buf + start, s->table->block_size);
		  md5_final(&m);
		  md5_digest(&m, digest);

		  n = rsync_lookup_2(n, weak, digest);
		}
	    }
	}
      if (n)
	{
	  /* Guess for the next block. */
	  s->guess = n + 1;

	  /* Does it make sense? */
	  if ( (s->guess == (s->table->all_nodes + s->table->alloc_size))
	       || (s->guess->length < s->table->block_size) )
	    s->guess = NULL;
	}
    }
  else
    {
      /* A smaller block. It could only match the final block. */
      s->guess = NULL;
      n = s->table->all_nodes + s->table->alloc_size - 1;
      if (size == n->length)
	{
	  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);

	  if (weak == n->sum_weak)
	    {
	      struct md5_ctx m;
	      UINT8 digest[MD5_DIGESTSIZE];

	      md5_init(&m);
	      md5_update(&m, s->buf + start, size);
	      md5_final(&m);
	      md5_digest(&m, digest);

	      if (!memcmp(n->sum_md5, digest, RSYNC_SUM_LENGTH))
		return n;
	    }
	}
    }
  return NULL;
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
	    UINT32 block_size;
	    
	    memcpy(s->buf + s->pos, input, left);
	    input += left;
	    length -= left;
	    s->pos = 0;
	    
	    s->count = READ_UINT32(s->buf);
	    block_size = READ_UINT32(s->buf + 4);
	    s->remainder = READ_UINT32(s->buf + 8);

	    if ( (s->count > s->max_count)
		 || (s->block_size > s->max_block_size)
		 || (s->remainder >= s->block_size))
	      return RSYNC_INPUT_ERROR;

	    s->table = make_rsync_table(s->count, block_size);
	    
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
	    s->pos = length;
	    return RSYNC_PROGRESS;
	  }
	else
	  {
	    node = rsync_add_entry(s->table, input);
	    length -= RSYNC_ENTRY_SIZE;
	    input += RSYNC_ENTRY_SIZE;
	  }
	
	node->length = s->block_size;
	
	if (s->table->size == s->table->alloc_size)
	  {
	    if (s->remainder)
	      node->length = s->remainder;
	    
	    return length ? RSYNC_INPUT_ERROR : RSYNC_DONE;
	  }
      }
  return RSYNC_PROGRESS;
}

/* While searching, we have to keep a buffer of previous block of
 * data. Our buffer BUF consists of SIZE octets starting at start. The
 * currently hashed data starts at position I in the buffer.
 *
 * We may have less than one block of data available, in that case we
 * must collect more data before we can start searching. If we collect
 * more than buf_size (usually twice the block size), we output a
 * literal. */

/* When output is generated, one of the following states is entered:
 *
 *  Pending output        Data left in the buffer
 *
 *   EOF                   Nothing
 *
 *   BLOCK                 Nothing
 *
 *   LITERAL, data, EOF    Nothing
 *
 *   LITERAL, data, BLOCK  Nothing
 *
 *   LITERAL, data         One block
 *
 */


enum rsync_send_mode
{
  /* Modes consuming input */
  /* Less than one block hashed. */
  STATE_INITIAL,
  /* One block hashed, keep sliding the block over the input data. */
  STATE_SEARCH,

  /* Modes generating output */
  /* Output a token, then start over in STATE_INITIAL with an empty
   * buffer. */
  STATE_TOKEN,

  /* Output a literal, then goto STATE_TOKEN */
  STATE_LITERAL_TOKEN,

  /* Output the data of a literal, then goto STATE_TOKEN */
  STATE_LITERAL_DATA_TOKEN,

  /* Output the data of a literal, then continue with STATE_SEARCH,
   * keeping buffered data. */
  STATE_LITERAL_DATA,

  /* Output a literal, then go on searching */
  STATE_LITERAL
};


int
rsync_send_init(struct rsync_send_state *s,
		struct rsync_table *table)
{
  assert(table->block_size <= 0xffffffffU/2);

  /* THe buffer must be at least twice the block size. */
  s->buf_size = table->block_size * 3;
  s->table = table;

  s->buf = malloc(s->buf_size);
  
  if (!s->buf)
    return RSYNC_MEMORY;
  
  s->size = 0;
  
  s->sum_a = s->sum_b = 0;
  s->state = STATE_INITIAL;

  return RSYNC_PROGRESS;
}

#define MIN3(a,b,c) (MIN(MIN((a),(b)),(c)))
#define MIN4(a,b,c,d) (MIN(MIN((a),(b)),MIN((c),(d))))

#if 0
static UINT32
rsync_send_copy(struct rsync_send_state *s,
		UINT32 *left, UINT32 limit, UINT8 *src)
{
  UINT32 avail = MIN3(*left, s->avail_out, limit);
  
  memcpy(s->next_out, src, avail);
  *left -=avail;
  s->next_out += avail;
  s->avail_out -= avail;

  return avail;
}
#endif

/* Copy to output buffer */
static UINT32
rsync_send_copy_out(struct rsync_send_state *s,
		    UINT32 length, const UINT8 *src)
{
  UINT32 avail = MIN(length, s->avail_out);
  memcpy(s->next_out, src, avail);
  s->next_out += avail;
  s->avail_out -= avail;

  return avail;
}

/* Copy from input buffer */
static UINT32
rsync_send_copy_in(struct rsync_send_state *s,
		   UINT32 length, UINT8 *dst)
{
  UINT32 avail = MIN(length, s->avail_in);
  memcpy(dst, s->next_in, avail);
  s->next_in += avail;
  s->avail_in -= avail;

  return avail;
}

#if 0
static void
rsync_send_shift(struct rsync_send_state *s,
		 UINT32 length)
{
  UINT32 left;
  assert(length <= s->size);

  left = s->size - length;
  if (left)
    {
      memmove(s->buf, s->buf+length, left);
    }
  s->size -= length;
}
#endif
/* Sends data from length_buffer. Returns RSYNC_DONE when done. */
static int
rsync_send_literal_length(struct rsync_send_state *s, int progress)
{
  UINT32 done;
	  
  assert(s->i < RSYNC_TOKEN_SIZE);

  done = rsync_send_copy_out(s,
			     RSYNC_TOKEN_SIZE - s->i,
			     s->length_buf + s->i);

  if (!done)
    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
  s->i += done;
  
  if (s->i < RSYNC_TOKEN_SIZE)
    /* More to do */
    return RSYNC_PROGRESS;
  else
    return RSYNC_DONE;
}

/* Sends s->literal octets from the buffer. Returns RSYNC_DONE when done. */
static int
rsync_send_literal_data(struct rsync_send_state *s, int progress)
{
  /* Transmit octets between I and LITERAL */
  UINT32 done;
  assert(s->i < s->literal);
	  
  done = rsync_send_copy_out(s,
			     s->literal - s->i,
			     s->buf + s->i);

  if (!done)
    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

  s->i += done;
  
  if (s->i < s->literal)
    /* More to do */
    return RSYNC_PROGRESS;

  else
    return RSYNC_DONE;
}

int
rsync_send(struct rsync_send_state *s, int flush)
{
  int progress = 0;

  for (;;)
    switch (s->state)
      {
      do_initial:
	s->size = 0;
	s->state = STATE_INITIAL;
	
      case STATE_INITIAL:
	{
	  /* The current hash does not include a complete block. We need more data. */
	  struct rsync_node *n;
	  UINT32 done = rsync_send_copy_in(s,
					   s->table->block_size - s->size,
					   s->buf + s->size);
	  rsync_update_1(&s->sum_a, &s->sum_b, done, s->buf + s->size);

	  if (done)
	    progress = 1;
	  
	  s->size += done;

	  if (s->size < s->table->block_size)
	    {
	      /* We don't have a complete block. */
	      assert(!s->avail_in);
	      if (flush)
		{
		  /* We reached end of input */
		do_eof:
		  WRITE_UINT32(s->token_buf, 0);
		  s->final = 1;
		  
		  if (s->size)
		    {
		      /* Length of literal */
		      WRITE_UINT32(s->length_buf, s->size);

		      goto do_literal_token;
		    }
		  else
		    goto do_token;
		}
	      return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	    }
	  
	  /* Check if we have a match already. */
	  n = rsync_lookup_block(s, 0, s->size);

	  if (n)
	    {
	      /* We have a match! */
	      UINT32 token = ~(n - s->table->all_nodes);

	      WRITE_UINT32(s->token_buf, token);

	      goto do_token;
	    }
	  else
	    goto do_search;

	  /* Can't happen */
	  abort();
	}
      do_search:
        s->state = STATE_SEARCH;
	s->guess = NULL;
	
      case STATE_SEARCH:
	{
	  /* The current hash is computed on the block
	   *
	   * buf[size - block_size...size]
	   */
	  assert(s->size >= s->table->block_size);
	  if (s->size < s->buf_size)
	    {
	      UINT32 avail = MIN(s->avail_in, s->buf_size - s->size);
	      UINT32 found;
	      struct rsync_node *n
		= rsync_search(&s->sum_a, &s->sum_b, s->table->block_size,
			       avail,
			       s->buf + s->size - s->table->block_size,
			       s->next_in,
			       &found, s->table->hash);
	      if (n)
		{
		  /* The block
		   *
		   *   buf[size - block_size + found...size] + next_in[0...found]
		   *
		   * might match */

		  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);

		  /* Found should be non-zero */
		  assert(found);

		  n = rsync_lookup_1(n, weak);

		  if (n)
		    {
		      struct md5_ctx m;
		      UINT8 digest[MD5_DIGESTSIZE];
		      UINT32 start = s->size + found - s->table->block_size;

		      /* NOTE: Don't bother examining our guess. */

		      md5_init(&m);
		      md5_update(&m, s->buf + start,
				 s->table->block_size - found);
		      md5_update(&m, s->next_in, found);
		      md5_final(&m);
		      md5_digest(&m, digest);

		      n = rsync_lookup_2(n, weak, digest);

		      if (n)
			{
			  /* Match found! */
			  /* Token is one-complement of the index */
			  UINT32 token = ~(n - s->table->all_nodes);

			  /* Block reference */
			  WRITE_UINT32(s->token_buf, token);

			  /* Length of literal */
			  WRITE_UINT32(s->length_buf, start);

			  /* Keep only the literal before the match */

			  s->size = start;
			  goto do_literal_token;
			}
		    }
		}
	      /* No match so far. Copy available data. */
	      if (avail)
		{
		  memcpy(s->buf + s->size, s->next_in, avail);
		  s->size += avail;
		  s->avail_in -= avail;
		  s->next_in += avail;
		  
		  progress = 1;
		}
	      else
		{
		  assert(!s->avail_in);
		  if (flush)
		    goto do_eof;
		  else
		    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
		}
	    }
	  else
	    {
	      /* Entire buffer filled, but no match. Make a literal
	       * out of all but the last block in the buffer */
	      UINT32 length = s->size - s->table->block_size;
	      WRITE_UINT32(s->length_buf, length);
	      s->literal = length;
	      
	      goto do_literal;
	    }
	  break;
	}
      do_literal:
        /* Octets of the length token that are transmitted */
        s->i = 0;

      case STATE_LITERAL:
	{
	  int res = rsync_send_literal_length(s, progress);

	  if (res != RSYNC_DONE)
	    return res;

	  progress = 1;
	  goto do_literal_data;
	}

      do_literal_data:
        s->i = 0;

      case STATE_LITERAL_DATA:
	{
	  UINT32 left;
	  int res = rsync_send_literal_data(s, progress);

	  if (res != RSYNC_DONE)
	    return res;
	  
	  left = s->literal < s->size;
	  assert(left);
	  
	  memmove(s->buf, s->buf + s->literal, left);
	  s->size = left;

	  goto do_search;
	}
      do_literal_token:
        s->i = 0;
	
      case STATE_LITERAL_TOKEN:
	{
	  int res = rsync_send_literal_length(s, progress);

	  if (res != RSYNC_DONE)
	    return res;

	  progress = 1;
	  goto do_literal_data_token;
	}

      do_literal_data_token:
        s->i = 0;

      case STATE_LITERAL_DATA_TOKEN:
	{
	  int res = rsync_send_literal_data(s, progress);

	  if (res != RSYNC_DONE)
	    return res;

	  progress = 1;
	  goto do_token;
	}
      do_token:
        s->i = 0;
      case STATE_TOKEN:
	
      }
}
#if 0
int
rsync_send(struct rsync_send_state *s, int flush)
{
  int progress = 0;

  for (;;)
    switch (s->state)
      {
      case STATE_LITERAL:
	{
	  /* Transmit octets between I and LITERAL */
	  assert(s->i < s->literal);
	  
	  s->i += rsync_send_copy_out(s,
				      s->literal - s->i,
				      s->buf + s->i);
	  
	  if (s->i < s->literal)
	    /* More to do */
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

#if 0
	  rsync_send_shift(s, s->literal);
#endif
	  
	  if (s->token_length)
	    {
	      s->state = STATE_TOKEN;
	      s->i = 0;
	    }
	  else
	    s->state = STATE_SEARCH;
	  
	  break;
	}
      case STATE_TOKEN:
	{
	  assert(s->i < s->token_length);
	  
	  s->i += rsync_send_copy_out(s,
				      s->token_length - s->i,
				      s->token_buf + s->i);
	  
	  if (s->i < s->token_length)
	    /* More to do */
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
	      
	  s->state = STATE_SEARCH;

	  break;
	}
      do_initial:
        /* Reset checksum */
        s->sum_a = sum->b = 0;
	s->size = 0;
	
      case STATE_INITIAL:
	{
	  /* The current hash does not include a complete block. We need more data. */
	  struct rsync_node *n;
	  UINT32 done = rsync_send_copy_in(s,
					   s->table->block_size - s->size,
					   s->buf + s->size);
	  rsync_update_1(&s->sum_a, &s->sum_b, done, s->buf + s->size);
	  s->size += done;

	  if ( (s->avail_in || !flush)
	       && (s->size < s->table->block_size) )
	    return RSYNC_PROGRESS;
	  
	  /* Check if we have a match already. */
	  n = rsync_lookup_block(s, 0, size);

	  if (n)
	    {
	      /* We have a match! */
	      UINT32 token = ~(n - s->table->all_nodes);

	      WRITE_UINT32(s->token_buf, token);

	      /* goto do_token; */
		
	      s->i = 0;
	      s->token_length = 4;
	      s->size = 0;
	      s->state = STATE_TOKEN;

	      /* Go on */
	      continue;
	    }
	  else
	    goto do_search;
	}
      do_search:
        s->state = STATE_SEARCH;

      case STATE_SEARCH:
	{
	  /* The current hash is computed on the block
	   *
	   * buf[size - block_size...size]
	   */
	  assert(s->size >= s->table->block_size);
	  if (s->size < s->buf_size)
	    {
	      UINT32 avail = MIN3(s->avail_in, s->buf_size - s->size);
	      UINT32 found;
	      struct rsync_node *n
		= rsync_search(&s->sum_a, &s->sum_b, s->table->block_size,
			       avail,
			       s->buf + s->size - s->table->block_size,
			       s->next_in,
			       &found, s->table->hash);
	      if (n)
		{
		  /* The block
		   *
		   *   buf[size - block_size + found...size] + next_in[0...found]
		   *
		   * might match */

		  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);
		  n = rsync_lookup_1(n, weak);

		  if (n)
		    {
		      struct md5_ctx m;
		      UINT8 digest[MD5_DIGESTSIZE];
		      UINT32 start = s->size + found - s->table->block_size;

		      /* FIXME: Examine guess first */
		      md5_init(&m);
		      md5_update(&m, s->buf + start,
				 s->table->block_size - found);
		      md5_update(&m, s->next_in, found);
		      md5_final(&m);
		      md5_digest(&m, digest);

		      n = rsync_lookup_2(n, weak, digest);

		      if (n)
			{
			  /* Match found! */
			  /* Token is one-complement of the index */
			  UINT32 token = ~(n - s->table->all_nodes);

			  /* Keep only the literal before the match */
			  s->size = start;
			  s->literal = start;
			  
			  s->state = STATE_LITERAL;

			  s->avail_in -= found;
			  s->next_in += found;

			  WRITE_UINT32(s->token_buf, token);
			  s->token_length = 4;

			  goto do_literal;
			}
		    }
		}
	      /* No match so far. Copy available data. */
	      memcpy(s->buf + s->size, s->next_in, avail);
	      s->size += avail;
	      s->avail_in -= avail;
	      s->next_in += avail;
	    }
	  else
	    {
	      /* Entire buffer filled, but no match. Make a literal
	       * out of all but the last block in the buffer */
	      UINT32 token = s->size - s->table->block_size;
	      s->literal = token;
	      s->i = 0;
	      WRITE_UINT32(s->token_buf, token);

	      s->state = STATE_TOKEN;
	    }
	}
      default:
	assert(0);
      }
}
#endif
#if 0
int
rsync_send(struct rsync_send_state *s, int flush)
{
  int progress = 0;

  for (;;)
    switch (s->state)
      {
      case STATE_LITERAL:
	{
	  /* Transmit octets between I and LITERAL */
	  assert(s->i < s->literal);
	  
	  s->i += rsync_send_copy_out(s,
				      s->literal - s->i,
				      s->buf + s->i);
	  
	  if (s->i < s->literal)
	    /* More to do */
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
	  rsync_send_shift(s, s->literal);
	  
	  if (s->token_length)
	    {
	      s->state = STATE_TOKEN;
	      s->i = 0;
	    }
	  else
	    s->state = (s->size < s->table->block_size)
	      ? STATE_INITIAL : STATE_SEARCH;
	  
	  break;
	}
      case STATE_TOKEN:
	{
	  assert(s->i < s->token_length);
	  
	  s->i += rsync_send_copy_out(s,
				      s->token_length - s->i,
				      s->token_buf + s->i);
	  
	  if (s->i < s->token_length)
	    /* More to do */
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
	      
	  s->state = (s->size < s->table->block_size)
	    ? STATE_INITIAL : STATE_SEARCH;

	  break;
	}
      case STATE_INITIAL:
	{
	  UINT32 done = rsync_send_copy_in(s,
					   s->table->block_size - s->i,
					   s->buf + s->i);
	  rsync_update_1(&s->sum_a, &s->sum_b, done, s->buf + s->i);
	  s->i += done;

	  if (s->i == s->table->block_size)
	    {
	      /* Check for match */
	      struct rsync_node *n = s->table->hash[HASH_SUM(s->sum_a, s->sum_b)];
	      if (n)
		{
		  /* The first block might match. */
		  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);

		  /* FIXME: Check s->guess block first */
		  n = rsync_lookup_1(n, weak);
		  if (n)
		    {
		      struct md5_ctx m;
		      UINT8 digest[MD5_DIGESTSIZE];
		      
		      md5_init(&m);
		      md5_update(&m, s->buf, s->table->block_size);
		      md5_final(&m);
		      md5_digest(&m, digest);

		      n = rsync_lookup_2(n, weak, digest);

		      if (n)
			{
			  /* We have a match! */
			  UINT32 token = n - s->table->all_nodes;

			  /* Next block is more likely to match. */
			  s->guess = n;
			  if (token + 1 < s->table->size)
			    s->guess++;

			  /* One's complement */
			  token = ~token;
			  WRITE_UINT32(s->token_buf, token);
			  s->i = 0;
			  s->token_length = 4;
			  s->size = 0;
			  s->state = STATE_TOKEN;

			  /* Go on */
			  continue;
			}
		    }
		}
	      s->state = STATE_SEARCH;
	    }
	  break;
	}
      case STATE_SEARCH:
	{
	  /* The current hash is computed on the block
	   *
	   * buf[size - block_size...size]
	   */
	  if (s->size < s->buf_size)
	    {
	      UINT32 avail = MIN(s->avail_in, s->table->block_size);
	      UINT32 found;
	      struct rsync_node *n
		= rsync_search(&s->sum_a, &s->sum_b, s->table->block_size,
			       avail,
			       s->buf + s->size - s->table->block_size,
			       s->next_in,
			       &found, s->table->hash);
	      if (n)
		{
		  /* The block
		   *
		   *   buf[size - block_size + found...size] + avail[0...found]
		   *
		   * might match */

		  UINT32 weak = COMBINE_SUM(s->sum_a, s->sum_b);
		  n = rsync_lookup_1(n, weak);

		  if (n)
		    {
		      struct md5_ctx m;
		      UINT8 digest[MD5_DIGESTSIZE];
		      
		      md5_init(&m);
		      md5_update(&m, s->buf + found,
				 s->table->block_size - found);
		      md5_update(&m, s->next_in, found);
		      md5_final(&m);
		      md5_digest(&m, digest);

		      n = rsync_lookup_2(n, weak, digest);

		      if (n)
			{
			  /* Match found! */
			  UINT32 token = n - s->table->all_nodes;
			  /* Token is one-complement of the index */
			  token = -(token + 1);

			  /* Make a literal of data up to the match */
			  s->size = s->size - s->table->block_size + found;
			  s->literal = s->size;
			  s->state = STATE_LITERAL;

			  s->avail_in -= found;
			  s->next_in += found;

			  token = -(token + 1);
			  WRITE_UINT32(s->token_buf, token);
			  s->literal =
			  s->state = STATE_TOKEN;

			  /* HERE!!! */
			  continue;
			}
		    }
		  /* Copy data up to the hash match */
		  avail += found;
		}
	      memcpy(s->buf + s->size, s->next_in, found);
	      s->size += found;
	      s->avail_in -= found;
	      s->next_in += found;
	    }
	  else
	    {
	      /* No match found. Make a literal out of all but the last block in the buffer */
	      UINT32 token = s->size - s->table->block_size;
	      s->literal = token;
	      s->i = 0;
	      WRITE_UINT32(s->token_buf, token);

	      s->state = STATE_TOKEN;
	    }
	}
      default:
	assert(0);
      }
}
#endif

#if 0

/* Returns amount of data copied. */
static UINT32
rsync_send_literal(struct rsync_send_state *s,
		   UINT32 *left)
{
  UINT32 avail;
  UINT32 total;
  
  while ( (avail = rsync_send_avail(s)) )
    {
      UINT32 done = rsync_send_copy(s, left, rsync_send_avail(s), s->buf + s->start);
      if (!done)
	return total;
      
      s->start += done;
      s->count -= done;
      total += done;
    }
}

/* Return the length of a continuous segment of our circular buffer. */
static UINT32
rsync_send_avail(struct rsync_send_state *s)
{
  if (s->start == s->buf_size)
    {
      s->start = 0;
      return s->count;
    }
  else
    {
      UINT32 tail = s->buf_size - s->start;
      return MIN(tail, s->count);
    }
}

int rsync_send(struct rsync_send_state *s, int flush)
{
  int progress = 0;
  
  for (;;)
    switch (s->state)
      {
      case STATE_LITERAL:
	{
	  /* s->literal is amount of data left to copy. */
	   
	  if (!s->avail_out)
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

	  if (s->count)
	    {
	      if (rsync_send_literal(s, &s->literal))
		progress = 1;
	    }
	  if (s->literal && !s->count)
	    {
	      if (rsync_send_copy(s, &s->literal, s->avail_in, s->next_in))
		{
		  progress = 1;
		  s->avail_in -= done;
		  s->next_in += done;
		}
	    }
	  if (s->literal)
	    /* More to do */
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
	  s->pos = 0;
	  if (s->token_left)
	    {
	      s->state = s->STATE_TOKEN;
	      s->hash_length = 0;
	    }
	  else
	    {
	      s->state = STATE_SEARCH;
	      s->hash_length = s->block_size;
	    }
	  break;
	}
      case STATE_TOKEN:
	{
	  rsync_send_copy(s, &s->token_left, s->token_left,
			  s->token_buf + TOKEN_LENGTH - s->token_left);
	  if (!s->token_left)
	    s->state = STATE_SEARCH;

	  break;
	}
      case STATE_SEARCH:
	{
	  UINT32 needed = s->table->block_size - s->hash_length;

	  if (needed)
	    {
	      /* We need to hash more data before searching. */

	      UINT32 avail = rsync_send_avail(s);
	      UINT32 chunk = MIN(needed, avail);	      
	      while (needed && (avail = 
		{
		  /* We have less than one block of data available */

		  rsync_update_1(&s->a_sum, &s->b_sum, s->buf + s->start, chunk);

		  s->hash_length += chunk;
		  needed -= chunk;
		}

	      if (needed)
		{
		  /* Need still more data */
		  UINT32 chunk = MIN(needed, s->avail_in);

		  assert(!s->count);
		  
		  rsync_update_1(&s->a_sum, &s->b_sum, s->next_in, chunk);
		  s->hash_length += chunk;
		  needed -= chunk;

		  if (needed)
		    {
		      memcpy(
		}


		  
		  
			
	  else
	    {
	      if (avail <= s->avail_out)
		{
		  memcpy(s->next_out, s->
	  UINT32 avail = MIN(s->avail_in, s->avail_out);

      
}
		   


{
  for (;;)
    switch (s->state)
      {
      case STATE_LITERAL:
	{
	  UINT32 avail = MIN(s->avail_in, s->avail_out);
	  if (s->i <= avail)
	    {
	      avail = s->i;
	      s->pos = 0;
	      s->state = STATE_SEARCH;
	    }
	  else
	    s->i -= avail;
	  
	  memcpy(s->next_out, s->next_in, avail);
	  s->next_out += avail;
	  s->next_in += avail;
	  s->avail_out -= avail;
	  s->avail_in -= avail;
	}
	break;
	      
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
	    else
	      {
		n = rsync_search(&s->a_sum, &s->b_sum, s->table->block_size,
				 

	  }
	}
      }
}
#endif
