/* generate.c
 *
 * Generate the list of checksums.
 *
 * $Id$
 */

#include "rsync.h"

#include <assert.h>
#include <string.h>

/* block count, blocksize, tail */
#define HEADER_SIZE 12

/* weak sum, md5 sum */
#define ENTRY_SIZE 20

static void
rsync_init_block(struct rsync_generate_state *s)
{
  s->a_sum = 0;
  s->c_sum = 0;
  md5_init(&s->block_sum);
}

static void
rsync_end_block(struct rsync_generate_state *s,
		UINT8 *dst)
{
  WRITE_UINT16(dst, s->a_sum);
  WRITE_UINT16(dst + 2, s->c_sum);
  md5_final(&s->block_sum);
  md5_digest(&s->block_sum, dst + 4);
}

static void
rsync_output_block(struct rsync_generate_state *s)
{
  assert(!s->buf_length);

  if (s->avail_out < ENTRY_SIZE)
  {
    rsync_end_block(s, s->buf);
    s->buf_length = ENTRY_SIZE;
    s->buf_pos = 0;
  }
  else
  {
    rsync_end_block(s, s->next_out);
    s->avail_out -= ENTRY_SIZE;
    s->next_out += ENTRY_SIZE;
  }
  rsync_init_block(s);
}

/* Update checksums.
 *
 * For input x_i, i = 0, ..., l-1, we calculate (modulo 2^16)
 *
 *   a_k = \sum_0^k x_i,
 *   b_k = \sum_0^k (l-i) x_i
 *
 * But in fact, we don't calculate all b_k, only the final
 * value b_{l-1}, and we have the identity (by changing order of summation(
 *
 *   b_{l-1} = \sum_0^{l-1} (l-i) x_i = \sum_0^{l-1} a_i
 *
 * So we keep track of the numbers c_k = \sum_0^k a_k rather than b_k.
 */

static void
rsync_update(struct rsync_generate_state *s,
	     UINT32 length)
{
  unsigned i;

  assert(length <= s->avail_in);

  md5_update(&s->block_sum, s->next_in, length);

  for (i = 0; i<length; i++)
  {
    s->a_sum += s->next_in[i] + RSYNC_CHAR_OFFSET;
    s->c_sum += s->a_sum;
  }

  s->a_sum &= 0xffff;
  s->c_sum &= 0xffff;

  s->offset += length;
  s->next_in += length;
  s->avail_in -= length;
}

#define OUT(c) (*s->next_out++ = (c), --s->avail_out)

#define DONE (s->offset == s->total_length)

int rsync_generate(struct rsync_generate_state *s)
{
  /* Have we maid any progress? */
  int progress = 0;
  
  for (;;)
    {
      if (s->avail_out && s->buf_length)
	{
	  /* Output previously prepared data */
	  unsigned left = s->buf_length - s->buf_pos;
    
	  if (s->avail_out >= left)
	    {
	      memcpy(s->next_out, s->buf + s->buf_pos, left);
	      s->next_out += left;
	      s->avail_out -= left;
	      s->buf_length = 0;
	      progress = 1;
	    } else {
	      memcpy(s->next_out, s->buf + s->buf_pos, s->avail_out);
	      s->next_out += s->avail_out;
	      s->buf_pos += s->avail_out;
	      s->avail_out = 0;

	      return DONE ? RSYNC_DONE : RSYNC_PROGRESS;
	    }
	}
      if (!s->avail_out && s->buf_length)
	/* We have buffered date, but no output space */
	return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

      /* Here, the internal buffer should be flushed. */
      assert(!s->buf_length);

      if (DONE)
	return s->avail_in ? RSYNC_INPUT_ERROR : RSYNC_DONE;
    
      /* Now we have some output space. */

      assert(s->left);
      
      if (!s->avail_in)
	return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

      /* And also some input to process. */

      if (s->avail_in < s->left)
	{
	  s->left -= s->avail_in;
	  rsync_update(s, s->avail_in);
	  return RSYNC_PROGRESS;
	}
      else
	{
	  rsync_update(s, s->left);
	  rsync_output_block(s);
	  if ( (s->offset + s->block_size) > s->total_length)
	    {
	      /* Next block is the final one, and shorter than one block */
	      s->left = s->total_length - s->offset;
	    }
	  else
	    s->left = s->block_size;

	  progress = 1;
	}
    }
}

int
rsync_generate_init(struct rsync_generate_state *s,
		    UINT32 block_size,
		    UINT32 size)
{
  /* Number of blocks */
  unsigned count = (size + block_size - 1) / block_size;
  unsigned tail = size % block_size;

  s->block_size = block_size;
  s->total_length = size;
  s->offset = 0;

  /* md5_init(&s->full_sum); */
  
  WRITE_UINT32(s->buf, count);
  WRITE_UINT32(s->buf + 4, block_size);
  WRITE_UINT32(s->buf + 8, tail);

  s->buf_length = HEADER_SIZE;
  s->buf_pos = 0;

  s->left = block_size;
  
  return 1;
}

      
      
