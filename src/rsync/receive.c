/* receive.c
 *
 * The receive end of the rsync algorithm. 
 *
 * $Id$ */

#include "rsync.h"

#include <assert.h>

/* Reading a partial token */
#define STATE_TOKEN 0

/* Reading a literal */
#define STATE_LITERAL 1

/* Copying a local block */
#define STATE_LOOKUP 2

/* Reading final md5 sum */
#define STATE_CHECKSUM 3

/* Results in error */
#define STATE_INVALID 4

static void
rsync_update(struct rsync_receive_state *s,
	     UINT32 length)
{
  md5_update(&s->full_sum, s->next_in, length);
  s->next_in += length;
  s->avail_in -= length;
}

#define GET() (assert(s->avail_in), s->avail_in--, *s->next_in++)

int
rsync_receive(struct rsync_receive_state *s)
{
  int progress = 0;
  
  for (;;)
    switch (s->state)
      {
      do_token:
	/* Here, i is octets read */
	s->token = 0;
	s->i = 0;
	s->state = STATE_TOKEN;
      case STATE_TOKEN:
	if (!s->avail_in)
	  return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	
	s->token = (s->token << 8) | GET();
	progress = 1;
	
	if (++s->i == 4)
	  {
	    if (!s->token)
	      goto do_checksum;
	    
	    else if (! (s->token & 0x80000000))
	      {
		s->i = s->token;
		goto do_literal;
	      }
	    else
	      {
		/* Index is one's complement */ 
		s->token = -(s->token + 1);
		goto do_lookup;
	      }
	  }
	break;

      do_literal:
	/* Here, i is the number of octets to read. */
	s->state = STATE_LITERAL;
      case STATE_LITERAL:
	{
	  UINT32 avail = MIN(s->avail_in, s->avail_out);
	  if (!avail)
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

	  if (avail < s->i)
	    {
	      memcpy(s->next_out, s->next_in, avail);
	      rsync_update(s, avail);
	      s->i -= avail;
	    }
	  else
	    {
	      memcpy(s->next_out, s->next_in, s->i);
	      rsync_update(s, s->i);
	      goto do_token;
	    }
	}
	break;

      do_lookup:
	s->state = STATE_LOOKUP;
	s->i = 0;
      case STATE_LOOKUP:
	{
	  UINT32 done;

	  if (!s->avail_out)
	    return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;
	  
	  switch (s->lookup(s->opaque, s->next_out, s->avail_out,
			    s->token, s->i, &done))
	    {
	    case 1:
	      rsync_update(s, done);
	      goto do_token;
	    case 0:
	      rsync_update(s, done);
	      s->i += done;
	      break;
	    case -1:
	      return RSYNC_INPUT_ERROR;
	    default:
	      assert(0);
	    }
	}
	break;
	  
      do_checksum:
	/* i is number of octets read */
	s->i = 0;
	md5_final(&s->full_sum);
	md5_digest(&s->full_sum, s->buf);
	s->state = STATE_CHECKSUM;
      case STATE_CHECKSUM:
	if (!s->avail_in)
	  return progress ? RSYNC_PROGRESS : RSYNC_BUF_ERROR;

	if (GET() != s->buf[s->i++])
	  return RSYNC_INPUT_ERROR;

	if (s->i == MD5_DIGESTSIZE)
	  {
	    s->state = STATE_INVALID;
	    return RSYNC_DONE;
	  }
	break;

      default:
	assert(0);
      }
}

void
rsync_receive_init(struct rsync_receive_state *s)
{
  s->state = STATE_TOKEN;
  s->i = 0;
}
