/* charset.c
 *
 * Translate local characterset to and from utf8.
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "charset.h"

#include <assert.h>

static int local_charset;

void set_local_charset(int charset)
{
  local_charset = charset;
}

UINT32 local_to_ucs4(int c)
{
  switch (local_charset)
    {
    case CHARSET_US_ASCII:
    case CHARSET_LATIN1:
      return (UINT32) c;
    default:
      fatal("Internal error");
    };
}

/* NOTE: This function does not filter any control characters */
int ucs4_to_local(UINT32 c)
{
  switch (local_charset)
    {
    case CHARSET_US_ASCII:
      return (c < 0x80) ? c : -1;
    case CHARSET_LATIN1:
      return (c < 0x100) ? c : -1;
    default:
      fatal("Internal error");
    };
}

struct lsh_string *local_to_utf8(struct lsh_string s, int free)
{
  switch (local_charset)
    {
    case CHARSET_UTF8:
    case CHARSET_USASCII:
      return s;
    default:
      {
	UINT32 *chars = alloca(s->length * sizeof(UINT32));
	unsigned char *lengths = alloca(s->length);

	UINT32 total = 0;
	{
	  int i;
	
	  /* First convert to ucs-4, and compute the length of the corresponding
	   * utf-8 string. */
	  for (i = 0; i<s->length; i++)
	    {
	      UINT32 c = local_to_ucs4(s->data[i]);
	      unsigned char l = 1;

	      if (c >= (1L<<7))
		{
		  l++;
		  if (c >= (1L<<11))
		    {
		      l++;
		      if (c >= (1L<<16))
			{
			  l++;
			  if (c >= (1L<<21))
			    {
			      l++;
			      if (c >= (1L<<25))
				{
				  l++;
				  if (c >= (1L<<31))
				    fatal("Internal error!\n");
				}}}}}
	      chars[i] = c;
	      lengths[i] = l;
	      total += l;
	    }
	}
	{
	  struct lsh_string res = lsh_string_alloc(total);
	  int i, j;

	  for(i = j = 0; i<s->length; i++)
	    {
	      static const UINT8 *prefix
		= {0, 0xC0, 0xE0, 0xF0, 0xF8, 0xFc };
	      
	      UINT32 c = chars[i];
	      unsigned char l = lengths[i] - 1;
	      int k;
	      
	      for (k = l; k; k--)
		{
		  res->data[j+k] = 0x80 | (c & 0x3f);
		  c >>= 6;
		}
	      assert( !(prefix[l] & c) );
	      res->data[j] = prefix[l] | c;

	      j += lengths[i];
	    }
	  assert(j == total);

	  if (free)
	    lsh_string_free(s);

	  return res;
	}
      }
    }
}
  
  
struct lsh_string *utf8_to_local(struct lsh_string s, int free)
{
  int i;
  struct lsh_string *res;
  struct simple_buffer buffer;
  
  if (local_charset == CHARSET_UTF8)
    return s;

  /* The string can't grow when converted to local charset */
  res = lsh_string_alloc(s->length);

  simple_buffer_init(&buffer, s->length, s->data);

  for (i = 0; 1; i++)
    {
      UINT32 ucs4;

      switch(parse_utf8(&buffer, &ucs4))
	{
	case -1:
	  assert(i<res->length);
	  
	  res->length = i;
	  if (free)
	    lsh_string_free(s);

	  return res;

	case 1:
	  {
	    int local = ucs4_to_local(ucs4);

	    if (local >= 0)
	      {
		res->data[i] = local;
		break;
	      }
	    /* Fall through */
	  }
	case 0: /* Error */
	  lsh_string_free(res);
	  if (free)
	    lsh_string_free(s);
	  return 0;

	default:
	  fatal("Internal error!\n");
	}
    }
}
