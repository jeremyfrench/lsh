/* sexp_parse.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Ron Rivest, Niels Möller
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

#include "sexp_parser.h"

#include "format.h"
#include "parse_macros.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

/* Automatically generated files. */
#include "sexp_table.h"
#include "digit_table.h"

/* Returns the length of the segmant of characters of a class */
static UINT32 sexp_scan_class(struct simple_buffer *buffer, int class)
{
  UINT32 i;

  for (i=0; i<LEFT; i++)
    if (!(sexp_char_classes[HERE[i]] & class))
      break;

  return i;
}

static void sexp_skip_space(struct simple_buffer *buffer)
{
  ADVANCE(sexp_scan_class(buffer, CHAR_space));
}

/* Skip the following input character on input stream struct
 * simple_buffer *buffer, if it is equal to a given character. Return 1
 * on success, 0 on error. */
static int sexp_skip_char(struct simple_buffer *buffer, UINT8 expect)
{
  UINT8 c;
  
  if (!LEFT)
    {
      werror("sexp: Unexpected EOF when expecting character %x.\n",
	     expect);
      return 0;
    }
  c = GET();
  if (c != expect)
    {
      werror("sexp: Expected char %x, got %x.\n", expect, c);
      return 0;
    }

  return 1;
}

/* Parse one or more characters into a simple string as a token. */
static struct lsh_string *sexp_parse_token(struct simple_buffer *buffer)
{
  UINT32 length;
  struct lsh_string *token;
  
  assert(LEFT);
  assert(sexp_char_classes[*HERE] & CHAR_token_start);
  
  length = sexp_scan_class(buffer, CHAR_token);

  if (!length)
    {
      werror("sexp: Invalid token.\n");
      return NULL;
    }

  token = ssh_format("%ls", length, HERE);
  ADVANCE(length);

  return token;
}

/* Parse a decimal number */
static int sexp_parse_decimal(struct simple_buffer *buffer, UINT32 *value)
{
  unsigned length = sexp_scan_class(buffer, CHAR_digit);
  unsigned i;
  
  assert(length);
  
  if ((*HERE == '0') && (length != 1))
    {
      /* No leading zeros allowed */
      werror("sexp: Unexpected leading zeroes\n");
      return 0;
    }
  if (length > 8)
    {
      werror("sexp: Decimal number too long (%d digits, max is 8).\n",
	     length);
      return 0;
    }
  for (i = 0, *value = 0; i<length; i++)
    *value = *value * 10 + HERE[i] - '0';

  ADVANCE(length);
  return 1;
}

/* Reads a literal string of given length. */
static struct lsh_string *
sexp_parse_literal(struct simple_buffer *buffer, UINT32 length)
{
  struct lsh_string *res;
  
  if (LEFT < length)
    {
      werror("sexp: Unexpected EOF in literal.\n");
      return NULL;
    }

  res = ssh_format("%ls", length, HERE);
  ADVANCE(length);

  return res;
}

#define QUOTE_END -1
#define QUOTE_INVALID -2

static int sexp_dequote(struct simple_buffer *buffer)
{
  int c;

  if (!LEFT)
    return QUOTE_INVALID;
  
  c = GET();

 loop:
  switch (c)
	{
	default:
	  return c;
	case '"':
	  return QUOTE_END;
	case '\\':
	  if (!LEFT)
	    return QUOTE_INVALID;

	  switch( (c = GET()) )
	    {
	    case '\\':
	    case '"':
	    case '\'':
	      return c;
	    case 'b':
	      return 0x8;
	    case 't':
	      return 0x9;
	    case 'n':
	      return 0xa;
	    case 'v':
	      return 0xb;
	    case 'f':
	      return 0xc;
	    case 'r':
	      return 0xd;
	    case '\r':
	      /* Ignore */
	      if (!LEFT)
		return QUOTE_INVALID;
	      c = GET();
	      if (c == '\n')
		{ /* Ignore this too */
		  if (!LEFT)
		    return QUOTE_INVALID;
		  c = GET();
		}
	      goto loop;
	    case '\n':
	      /* Ignore */
	      if (!LEFT)
		return QUOTE_INVALID;
	      c = GET();
	      if (c == '\r')
		{ /* Ignore this too */
		  if (!LEFT)
		    return QUOTE_INVALID;
		  c = GET();
		}
	      goto loop;
	      
	    default:
	      /* Octal escape sequence */
	      {
		int value;
		unsigned i;
	    
		if (!(sexp_char_classes[c] & CHAR_octal))
		  {
		    werror("sexp: Invalid escape character in"
			   " quoted string: %x.\n", c);
		    return QUOTE_INVALID;
		  }

		if (LEFT < 2)
		  {
		    werror("sexp: Unexpected eof in octal escape sequence.\n");
		    return QUOTE_INVALID;
		  }
	    	      
		value = c - '0';
		for (i = 1; i<3; i++)
		  {
		    c = GET();
		    if (!(sexp_char_classes[c] & CHAR_octal))
		      {
			werror("sexp: Invalid character %x in"
			       " octal escape sequence.\n", c);
			return QUOTE_INVALID;
		      }
		    value = (value << 3) + (c - '0');
		  }
		return value;
	      }
	    }
	}
}
	
/* Reads a quoted string of given length. Handles ordinary C escapes.
 * Assumes that the starting '"' have been skipped already. */
static struct lsh_string *
sexp_parse_quoted_length(struct simple_buffer *buffer, UINT32 length)
{
  struct lsh_string *res;
  UINT32 i;
  
  res = lsh_string_alloc(length);
  
  for (i = 0; i < length; i++)
    {
      int c = sexp_dequote(buffer);

      if (c < 0)
	{
	  if (c == QUOTE_END)
	    werror("sexp: Quoted string is too short.\n");
	  lsh_string_free(res);
	  return NULL;
	}
      res->data[i] = (unsigned) c;
    }
  return res;
}

/* Reads a quoted string of indefinite length */
static struct lsh_string *
sexp_parse_quoted(struct simple_buffer *buffer)
{
  struct lsh_string *res;
  UINT32 length;
  UINT32 i;
  UINT8 *p;
  
  if (*HERE == '"')
    return lsh_string_alloc(0);

  /* We want a reasonable upper bound on the string to allocate.
   * Search for a double quote, not preceded by a backslash. */
  
  for (p = HERE; p < HERE + LEFT; )
    {
      p = memchr(p, '"', (HERE + LEFT) - p);
      if (!p)
	{
	  werror("sexp: Unexpected EOF in quoted string.\n");
	  return NULL;
	}
      if (p[-1] != '\\')
	break;

      p++;
    }

  length = p - HERE;
  res = lsh_string_alloc(length);

  for (i = 0; i<length; i++)
    {
      int c = sexp_dequote(buffer);

      switch (c)
	{
	case QUOTE_INVALID:
	  lsh_string_free(res);
	  return NULL;
	case QUOTE_END:
	  res->length = i;
	  return res;
	default:
	  res->data[i] = (unsigned) c;
	}
    }

  /* We haven't seen the ending double quote yet. We must be looking at it now. */
  if (!sexp_skip_char(buffer, '"'))
    fatal("Internal error!\n");
  
  return res;
}

static int sexp_dehex(struct simple_buffer *buffer)
{
  unsigned i;
  int value = 0;

  for (i = 0; i<2; i++)
    {
      int c;
      
      sexp_skip_space(buffer);

      if (!LEFT)
	{
	  werror("sexp: Unexpected EOF in hex string.\n");
	  return HEX_INVALID;
	}

      c = hex_digits[GET()];
      
      switch (c)
	{
	case HEX_END:
	  if (!i)
	    return HEX_END;
	  /* Fall through */
	case  HEX_INVALID:
	  return HEX_INVALID;
	default:
	  value = (value << 4) | c;
	}
    }
  return value;
}

/* Reads a hex string of given length. Handles ordinary C escapes.
 * Assumes that the starting '#' have been skipped already. */
static struct lsh_string *
sexp_parse_hex_length(struct simple_buffer *buffer, UINT32 length)
{
  struct lsh_string *res;
  UINT32 i;
  
  res = lsh_string_alloc(length);
  
  for (i = 0; i < length; i++)
    {
      int c =  sexp_dehex(buffer);

      if (c < 0)
	{
	  if (c == HEX_END)
	    werror("sexp: Hex string is too short.\n");
	  lsh_string_free(res);
	  return NULL;
	}
      res->data[i] = (unsigned) c;
    }
  return res;
}

/* Reads a hex string of indefinite length */
static struct lsh_string *
sexp_parse_hex(struct simple_buffer *buffer)
{
  struct lsh_string *res;
  
  UINT32 length = sexp_scan_class(buffer, CHAR_hex | CHAR_space);
  UINT32 terminator = buffer->pos + length;

  UINT32 i;
  
  if ( (length == LEFT)
       || (HERE[terminator] != '#'))
    {
      werror("sexp: Unexpected EOF in hex string.\n");
      return NULL;
    }

  /* The number of digits, divided by two, rounded upwards,
   * is an upper limit on the length. */

  length = (length + 1) / 2;

  res = lsh_string_alloc(length);

  for (i = 0; i < length; i++)
    {
      int c = sexp_dehex(buffer);

      switch (c)
	{
	case HEX_INVALID:
	  lsh_string_free(res);
	  return NULL;
	case HEX_END:
	  res->length = i;
	  return res;
	default:
	  res->data[i] = (unsigned) c;
	}
    }

  assert(sexp_scan_class(buffer, CHAR_space) == (terminator - buffer->pos));
  buffer->pos = terminator + 1;

  return res;
}

struct base64_state
{
  /* Bits are shifted into the buffer from the right, 6 at a time */
  unsigned buffer;
  /* Bits currently in the buffer */
  unsigned bits;

  UINT8 terminator;
};

#define BASE64_INIT(t) {0, 0, (t)}

/* Extracts one octet from the base64 encoded input. */
static int sexp_decode_base64(struct simple_buffer *buffer,
			      struct base64_state *state)
{
  int res;

  assert(state->bits <= 8);

  while (state->bits < 8)
    {
      UINT8 c;
      int digit;
      
      if (!LEFT)
	return BASE64_INVALID;
      
      c = GET();
      if (c == state->terminator)
	{
	  /* Check for unused bits */
	  if (state->bits && ((1<<state->bits) & state->buffer))
	    {
	      werror("sexp: Base64 terminated with %d leftover bits.\n",
		     state->bits);
	      return BASE64_INVALID;
	    }
	  return BASE64_END;
	}

      digit = base64_digits[c];

      switch (digit)
	{
	case BASE64_SPACE:
	  continue;
	case BASE64_INVALID:
	  return BASE64_INVALID;
	default:
	  state->buffer = (state->buffer << 6) | digit;
	  state->bits += 6;
	}
    }
  res = (state->buffer >> (state->bits - 8)) & 0xff;
  state->bits -= 8;

  return res;
}

/* Reads a base64-encoded string of given length. */
static struct lsh_string *
sexp_parse_base64_length(struct simple_buffer *buffer,
			UINT32 length,
			UINT8 terminator)
{
  struct base64_state state = BASE64_INIT(terminator);

  struct lsh_string *res;
  UINT32 i;
  
  res = lsh_string_alloc(length);
  
  for (i = 0; i < length; i++)
    {
      int c = sexp_decode_base64(buffer, &state);

      if (c < 0)
	{
	  if (c == BASE64_END)
	    werror("sexp: Base string is too short.\n");
	  lsh_string_free(res);
	  return NULL;
	}
      res->data[i] = (unsigned) c;
    }
  return res;
}

/* Reads a base64-encoded string of indefinite length. */
static struct lsh_string *
sexp_parse_base64(struct simple_buffer *buffer, UINT8 delimiter)
{
  struct base64_state state = BASE64_INIT(delimiter);
  struct lsh_string *res;

  UINT32 length = sexp_scan_class(buffer, CHAR_base64 | CHAR_space);
  UINT32 terminator = buffer->pos + length;

  UINT32 i;
  
  if ( (length == LEFT)
       || (HERE[terminator] != delimiter))
    {
      werror("sexp: Unexpected EOF in base64 string.\n");
      return NULL;
    }

  /* The number of digits, multiplied by 3/4, rounded upwards,
   * is an upper limit on the length. */

  length = ( (length + 1) * 3) / 4;

  res = lsh_string_alloc(length);

  for (i = 0; i < length; i++)
    {
      int c = sexp_decode_base64(buffer, &state);

      switch (c)
	{
	case BASE64_INVALID:
	  lsh_string_free(res);
	  return NULL;
	case BASE64_END:
	  res->length = i;
	  return res;
	default:
	  res->data[i] = (unsigned) c;
	}
    }

  assert(sexp_scan_class(buffer, CHAR_base64_space) == (terminator - buffer->pos));
  buffer->pos = terminator + 1;

  return res;
}
  
/* Reads and returns a simple string from the input stream, using the
 * canonical encoding. */
static struct lsh_string *
sexp_parse_string_canonical(struct simple_buffer *buffer)
{
  UINT32 length;
      
  if (sexp_parse_decimal(buffer, &length)
      && sexp_skip_char(buffer, ':'))
    return sexp_parse_literal(buffer, length);

  return NULL;
}

static struct lsh_string *
sexp_parse_string_advanced(struct simple_buffer *buffer)
{
  int class;
  
  if (!LEFT)
    return NULL;

  class = sexp_char_classes[*HERE];

  if (class & CHAR_token_start)
    return sexp_parse_token(buffer);

  if (class & CHAR_digit)
    {
      UINT32 length;
      if (!sexp_parse_decimal(buffer, &length))
	return NULL;

      switch(GET())
	{
	case '|':
	  return sexp_parse_base64_length(buffer, length, '|');
	case '#':
	  return sexp_parse_hex_length(buffer, length);
	case '"':
	  return sexp_parse_quoted_length(buffer, length);
	case ':':
	  return sexp_parse_literal(buffer, length);
	default:
	  werror("sexp: Invalid prefixed string.\n");
	  return NULL;
	}
    }
      
  switch(GET())
    {
    case '|':
      return sexp_parse_base64(buffer, '|');
    case '#':
      return sexp_parse_hex(buffer);
    case '"':
      return sexp_parse_quoted(buffer);
    default:
      return NULL;
    }
}

static struct sexp *
sexp_parse_display_canonical(struct simple_buffer *buffer)
{
  struct lsh_string *display;

  sexp_skip_space(buffer);
  
  display = sexp_parse_string_canonical(buffer);

  if (display)
    {
      sexp_skip_space(buffer);
      if (sexp_skip_char(buffer, ']'))
	{
	  struct lsh_string *contents;
	  
	  sexp_skip_space(buffer);
	  contents = sexp_parse_string_canonical(buffer);

	  if (contents)
	    return make_sexp_string(display, contents);
	}
      lsh_string_free(display);
    }

  return NULL;
}

static struct sexp *
sexp_parse_display_advanced(struct simple_buffer *buffer)
{
  struct lsh_string *display = sexp_parse_string_advanced(buffer);

  if (display)
    {
      struct lsh_string *contents;

      if (sexp_skip_char(buffer, ']')
     	  && ((contents = sexp_parse_string_advanced(buffer))))
	return make_sexp_string(display, contents);

      lsh_string_free(display);
    }
  
  return NULL;
}

struct parse_node
{
  struct parse_node *prev;
  struct sexp *item;
};

struct parse_list
{
  struct parse_node *tail;
  unsigned count;
};

#define PARSE_LIST_INIT { NULL, 0 }

static struct sexp *build_parse_vector(struct parse_list *p)
{
  struct object_list *l = alloc_object_list(p->count);
 
  unsigned i = p->count;
  struct parse_node *n = p->tail;
   
  while (n)
    {
      struct parse_node *old = n;
      
      assert(i);
      LIST(l)[--i] = &n->item->super;
      old = n;
      n = n->prev;
      
      lsh_space_free(old);
    }
  assert(!i);
  
  return sexp_v(l);
}

static void parse_list_free(struct parse_list *p)
{
  struct parse_node *n = p->tail;
  
  while (n)
    {
      struct parse_node *old = n;

      /* FIXME: Could we do KILL(n->item); here? */
      n = n->prev;
      lsh_space_free(old);
    }
}

static void parse_list_add(struct parse_list *p, struct sexp *e)
{
  struct parse_node *n;

  NEW_SPACE(n);
  n->prev = p->tail;
  n->item = e;
  p->tail = n;

  p->count++;
}

static struct sexp *sexp_parse_list_canonical(struct simple_buffer *buffer)
{
  struct parse_list p = PARSE_LIST_INIT;

  while (LEFT)
    {
      struct sexp *e;
      
      if (*HERE == ')')
	return build_parse_vector(&p);

      e = sexp_parse_canonical(buffer);
      if (!e)
	{
	  parse_list_free(&p);
	  return NULL;
	}
      parse_list_add(&p, e);
    }
  werror("sexp: Unexpected EOF (missing ')')\n");
  
  parse_list_free(&p);
  return NULL;
}

static struct sexp *sexp_parse_list_advanced(struct simple_buffer *buffer)
{
  struct parse_list p = PARSE_LIST_INIT;

  while (LEFT)
    {
      struct sexp *e;
      
      if (*HERE == ')')
	return build_parse_vector(&p);

      e = sexp_parse_advanced(buffer);
      if (!e)
	{
	  parse_list_free(&p);
	  return NULL;
	}
      parse_list_add(&p, e);

      sexp_skip_space(buffer);
    }
  werror("sexp: Unexpected EOF (missing ')')\n");
  
  parse_list_free(&p);
  return NULL;
}

struct sexp *sexp_parse_canonical(struct simple_buffer *buffer)
{
  if (!LEFT)
    {
      werror("sexp: Unexpected EOF.\n");
      return NULL;
    }

  if (sexp_char_classes[*HERE] & CHAR_digit)
    {
      struct lsh_string *s = sexp_parse_string_canonical(buffer);
      return s ? make_sexp_string(NULL, s) : NULL;
    }
  
  switch(GET())
    {
    case '(':
      return sexp_parse_list_canonical(buffer);
    case '[':
      return sexp_parse_display_canonical(buffer);
    default:
      werror("sexp: Syntax error.\n");
      return NULL;
    }
}

static struct sexp *sexp_decode_transport(struct simple_buffer *buffer)
{
  struct lsh_string *s = sexp_parse_base64(buffer, '}');
  struct simple_buffer inner;
  struct sexp *e;
  
  if (!s)
    return NULL;

  simple_buffer_init(&inner, s->length, s->data);

  e = sexp_parse_canonical(&inner);

  if (!parse_eod(&inner))
    e = NULL;
  
  lsh_string_free(s);
  return e;
}

struct sexp *sexp_parse_transport(struct simple_buffer *buffer)
{
  if (!LEFT)
    {
      werror("sexp: Unexpected EOF.\n");
      return NULL;
    }

  if (*HERE == '{')
    {
      ADVANCE(1);
      return sexp_decode_transport(buffer);
    }

  return sexp_parse_canonical(buffer);
}

struct sexp *sexp_parse_advanced(struct simple_buffer *buffer)
{
  if (!LEFT)
    {
      werror("sexp: Unexpected EOF.\n");
      return NULL;
    }

  switch (*HERE)
    {
    case '(':
      ADVANCE(1);
      return sexp_parse_list_advanced(buffer);
    case '{':
      ADVANCE(1);
      return sexp_decode_transport(buffer);
    case '[':
      ADVANCE(1);
      return sexp_parse_display_advanced(buffer);
    default:
      {
	struct lsh_string *s = sexp_parse_string_advanced(buffer);
	return s ? make_sexp_string(NULL, s) : NULL;
      }
    }
}

