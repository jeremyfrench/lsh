/* format.c
 *
 *
 *
 * $Id$ */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "format.h"

#include "list.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

struct lsh_string *ssh_format(const char *format, ...)
{
  va_list args;
  UINT32 length;
  struct lsh_string *packet;

  va_start(args, format);
  length = ssh_vformat_length(format, args);
  va_end(args);

#if DEBUG_ALLOC
  packet = lsh_string_alloc_clue(length, format);
#else
  packet = lsh_string_alloc(length);
#endif
  
  va_start(args, format);
  ssh_vformat_write(format, length, packet->data, args);
  va_end(args);

  return packet;
}

UINT32 ssh_format_length(const char *format, ...)
{
  va_list args;
  UINT32 length;

  va_start(args, format);
  length = ssh_vformat_length(format, args);
  va_end(args);

  return length;
}

void ssh_format_write(const char *format, UINT32 length, UINT8 *buffer, ...)
{
  va_list args;
  
  va_start(args, buffer);
  ssh_vformat_write(format, length, buffer, args);
  va_end(args);
}
     
static int write_decimal_length(UINT8 *buffer, UINT32 n);

UINT32 ssh_vformat_length(const char *f, va_list args)
{
  UINT32 length = 0;

  while(*f)
    {
      if (*f == '%')
	{
	  int literal = 0;
	  int decimal = 0;
	  int unsigned_form = 0;
	  int hex = 0;
	  
	  while(*++f)
	    {
	      switch (*f)
		{
		case 'l':
		  literal = 1;
		  break;
		case 'd':
		  decimal = 1;
		  break;
		case 'f':
		  /* Do nothing */
		  break;
		case 'u':
		  unsigned_form = 1;
		  break;
		case 'x':
		  hex = 1;
		  break;
		default:
		  goto end_options;
		}
	    }
end_options:

	  if (literal && decimal)
	    fatal("Internal error!\n");
	  
	  switch(*f++)
	    {
	    case 'c':
	      (void) va_arg(args, int);
	      /* Fall through */
	    case '%':
	      length++;
	      break;

	    case 'i':
	      {
		UINT32 i = va_arg(args, UINT32);
		if (decimal)
		  length += format_size_in_decimal(i);
		else
		  length += 4;
		break;
	      }

	    case 's':
	      {
		UINT32 l = va_arg(args, UINT32); /* String length */ 
		(void) va_arg(args, const UINT8 *);    /* data */

		length += l;

		if (hex)
		  length += l;

		if (decimal)
		  length += format_size_in_decimal(l) + 1;
		else if (!literal)
		  length += 4;

		break;
	      }
	    case 'S':
	      {
		struct lsh_string *s = va_arg(args, struct lsh_string *);
		length += s->length;

		if (hex)
		  length += s->length;
		
		if (decimal)
		  length += format_size_in_decimal(s->length) + 1;
		else if (!literal)
		  length += 4;
		
		break;
	      }
	    case 'z':
	      {
		unsigned l = strlen(va_arg(args, const char *));
		length += l;

		if (decimal)
		  length += format_size_in_decimal(l) + 1;
		
		else if (!literal)
		  length += 4;
		break;
	      }
	    case 'r':
	      {
		UINT32 l = va_arg(args, UINT32); 
		length += l;
		(void) va_arg(args, UINT8 **);    /* pointer */

		if (decimal)
		  length += format_size_in_decimal(l) + 1;
		else if (!literal)
		  length += 4;

		break;
	      }
	    case 'a':
	      {
		int atom = va_arg(args, int);
		int l;
		
		assert(atom);

		l = get_atom_length(atom);
		length += l;

		if (decimal)
		  length += format_size_in_decimal(l) + 1;
		else if (!literal)
		  length += 4;

		break;
	      }
	    case 'A':
	      {
		struct int_list *l = va_arg(args, struct int_list *);
		UINT32 n, i;

		if (decimal)
		  fatal("ssh_format: Decimal lengths not supported for %%A\n");
		
		for(n = i =0; i < LIST_LENGTH(l); i++)
		  {
		    if (LIST(l)[i])
		      {
			n++;
			length += get_atom_length(LIST(l)[i]);
		      }
		  }
		if (n)
		  /* One ','-character less than the number of atoms */
		  length += (n-1);
		    
		if (!literal)
		  length += 4;

		break;
	      }
	    case 'n':
	      {
		MP_INT *n = va_arg(args, MP_INT*);

		/* Calculate length of written number */
		unsigned l;
		if (unsigned_form)
		  {
		    assert(mpz_sgn(n) >= 0);
		    l = bignum_format_u_length(n);
		  }
		else
		  l = bignum_format_s_length(n);

		length += l;

		/* Decimal not supported. */
		assert(!decimal);
#if 0
		if (decimal)
		  {
		    length += format_size_in_decimal(l) + 1;
		  }
		else
#endif
		if (!literal)
		  length += 4;

		break;
	      }
	    default:
	      fatal("ssh_vformat_length: bad format string");
	      break;
	    }
	}
      else
	{
	  length++;
	  f++;
	}
    }
  return length;
}

void ssh_vformat_write(const char *f, UINT32 size, UINT8 *buffer, va_list args)
{
  UINT8 *start = buffer;
  
  while(*f)
    {
      if (*f == '%')
	{
	  int literal = 0;
	  int do_free = 0;
	  int decimal = 0;
	  int hex = 0;
	  int unsigned_form = 0;
	  
	  while(*++f)
	    {
	      switch (*f)
		{
		case 'l':
		  literal = 1;
		  break;
		case 'd':
		  decimal = 1;
		  break;
		case 'f':
		  do_free = 1;
		  break;
		case 'u':
		  unsigned_form = 1;
		  break;
		case 'x':
		  hex = 1;
		  break;
		default:
		  goto end_options;
		}
	    }
	end_options:
		  
	  if (literal && decimal)
	    fatal("Internal error!\n");

	  switch(*f++)
	    {
	    case 'c':
	      *buffer++ = va_arg(args, int);

	      break;
	    case '%':
	      *buffer++ = '%';

	      break;

	    case 'i':
	      {
		UINT32 i = va_arg(args, UINT32);
		if (decimal)
		  {
		    unsigned length = format_size_in_decimal(i);
		    format_decimal(length, buffer, i);
		    buffer += length;
		  }
		else
		  {
		    WRITE_UINT32(buffer, i);
		    buffer += 4;
		  }
		break;
	      }

	    case 's':
	      {
		UINT32 size = va_arg(args, UINT32);
		const UINT8 *data = va_arg(args, const UINT8 *);

		UINT32 length = hex ? (2*size) : size;

		if (decimal)
		  buffer += write_decimal_length(buffer, length);
		else if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		if (hex)
		  format_hex_string(buffer, size, data);
		else
		  memcpy(buffer, data, size);
		
		buffer += length;

		break;
	      }
	    case 'S':
	      {
		struct lsh_string *s = va_arg(args, struct lsh_string *);
		UINT32 length = s->length;

		if (hex)
		  length *= 2;

		if (decimal)
		  buffer += write_decimal_length(buffer, length);

		else if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		if (hex)
		  format_hex_string(buffer, s->length, s->data);
		else
		  memcpy(buffer, s->data, s->length);

		buffer += length;

		if (do_free)
		  lsh_string_free(s);

		break;
	      }
	    case 'z':
	      {
		const char *s = va_arg(args, const char *);
		UINT32 length = strlen(s);

		if (decimal)
		  buffer += write_decimal_length(buffer, length);

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		memcpy(buffer, s, length);
		buffer += length;

		break;
	      }
	    case 'r':
	      {
		UINT32 length = va_arg(args, UINT32);
		UINT8 **p = va_arg(args, UINT8 **);

		if (decimal)
		  buffer += write_decimal_length(buffer, length);
		else if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		if (p)
		  *p = buffer;
		buffer += length;

		break;
	      }
	    
	    case 'a':
	      {
		UINT32 length;
		int atom = va_arg(args, int);
		
		assert(atom);

		length = get_atom_length(atom);

		if (decimal)
		  buffer += write_decimal_length(buffer, length);
		else if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		memcpy(buffer, get_atom_name(atom), length);
		buffer += length;

		break;
	      }
	    case 'A':
	      {
		struct int_list *l = va_arg(args, struct int_list *);
		UINT8 *start = buffer; /* Where to store the length */
		UINT32 n, i;
		
		if (decimal)
		  fatal("ssh_format: Decimal lengths not supported for %%A\n");

		if (!literal)
		  buffer += 4;
		
		for(n = i = 0; i < LIST_LENGTH(l); i++)
		  {
		    if (LIST(l)[i])
		      {
			UINT32 length = get_atom_length(LIST(l)[i]);
			
			if (n)
			  /* Not the first atom */
			  *buffer++ = ',';

			memcpy(buffer, get_atom_name(LIST(l)[i]), length);
			buffer += length;

			n++;
		      }
		  }

		if (!literal)
		  {
		    UINT32 total = buffer - start - 4;
		    WRITE_UINT32(start, total);
		  }
		break;
	      }
	    case 'n':
	      {
		MP_INT *n = va_arg(args, MP_INT *);
		UINT32 length;
		UINT8 *start = buffer; /* Where to store the length */

		/* Decimal not supported */
		assert(!decimal);
		
		if (!literal)
		  buffer += 4;

		if (unsigned_form)
		  {
		    assert(mpz_sgn(n) >= 0);
		
		    length = bignum_format_u(n, buffer);
		  }
		else
		  length = bignum_format_s(n, buffer);
		
		buffer += length;

		if (!literal)
		  WRITE_UINT32(start, length);

		break;
	      }
	    default:
	      fatal("ssh_vformat_write: bad format string");
	      break;
	    }
	}
      else
	{
	  *buffer++ = *f++;
	}
    }
  
  assert(buffer == start + size);
}

unsigned format_size_in_decimal(UINT32 n)
{
  int i;
  int e;
  
  /* Table of 10^(2^n) */
  static const UINT32 powers[] = { 10UL, 100UL, 10000UL, 100000000UL };

#define SIZE (sizeof(powers) / sizeof(powers[0])) 

  /* Determine the smallest e such that n < 10^e */
  for (i = SIZE - 1 , e = 0; i >= 0; i--)
    {
      if (n >= powers[i])
	{
	  e += 1UL << i;
	  n /= powers[i];
	}
    }

#undef SIZE
  
  return e+1;
}


void
format_hex_string(UINT8 *buffer, UINT32 length, const UINT8 *data)
{
  static const UINT8 hexchars[16] = "0123456789abcdef";
  UINT32 i;

  for (i = 0; i < length; i++)
    {
      *buffer++ = hexchars[ (data[i] & 0xf0) >> 4 ];
      *buffer++ = hexchars[ data[i] & 0x0f ];
    }
}

void format_decimal(unsigned length, UINT8 *buffer, UINT32 n)
{
  unsigned i;
  
  for (i = 0; i<length; i++)
    {
      buffer[length - i - 1] = '0' + n % 10;
      n /= 10;
    }
}

static int write_decimal_length(UINT8 *buffer, UINT32 n)
{
  int length = format_size_in_decimal(n);

  format_decimal(length, buffer, n);
  buffer[length] = ':';

  return length + 1;
}

const char *
lsh_get_cstring(const struct lsh_string *s)
{
  return (s && !memchr(s->data, '\0', s->length) ? s->data : NULL);
}

int
lsh_string_eq(const struct lsh_string *a, const struct lsh_string *b)
{
  return ( (a->length == b->length)
	   && !memcmp(a->data, b->data, a->length));
}

int
lsh_string_eq_l(const struct lsh_string *a,
		UINT32 length, const UINT8 *b)
{
  return ( (a->length == length)
	   && !memcmp(a->data, b, length));
}

int
lsh_string_prefixp(const struct lsh_string *prefix,
		   const struct lsh_string *s)
{
  return ( (prefix->length <= s->length)
	   && !memcmp(prefix->data, s->data, prefix->length));
}

struct lsh_string*
lsh_string_colonize(struct lsh_string *s, int every, int freeflag)
{
  UINT32 i = 0;
  UINT32 j = 0;

  struct lsh_string *packet;
  UINT32 length;
  int colons;

  /* No of colonds depens on length, 0..every => 0, 
   * every..2*every => 1 */

  colons = s->length ? (s->length - 1) / every : 0;
  length = s->length + colons;

  packet = lsh_string_alloc(length);

  for (; i<s->length; i++)
    {
      assert( j < length ); /* Extra sanity check */

      if (i && !(i%every))  /* Every nth position except at the beginning */
	packet->data[j++] = ':';

      assert( j < length ); /* Extra sanity check */
      packet->data[j++] = s->data[i];
    }

  if (freeflag) /* Throw away the source string? */
    lsh_string_free( s );

  return packet;
}

static UINT8 
lsh_string_bubblebabble_c( struct lsh_string *s, UINT32 i )
{ 
  /* Recursive, should only be used for small strings */

  UINT8 c;
  UINT32 j;
  UINT32 k;

  assert( 0 != i);

  if (1==i)
    return 1;

  j = i*2-3-1;
  k = i*2-2-1;

  assert( j < s->length && k < s->length );

  c = lsh_string_bubblebabble_c( s, i-1 );
 
  return (5*c + (s->data[j]*7+s->data[k])) % 36;
}

struct lsh_string*
lsh_string_bubblebabble(struct lsh_string *s, int freeflag)
{
  /* Implements the Bubble Babble Binary Data Encoding by Huima as
   * posted to the secsh list in August 2001 by Lehtinen.*/
 
  UINT32 i = 0;
  UINT32 babblelen = 2 + 6*(s->length/2) + 3;
  struct lsh_string *p = lsh_string_alloc( babblelen );

  UINT8 *r = p->data;
  UINT8 *q = s->data; 

  UINT8 a;
  UINT8 b;
  UINT8 c;
  UINT8 d;
  UINT8 e;

  char vowels[6] = { 'a', 'e', 'i', 'o', 'u', 'y' };

  char cons[18] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k',  'l', 'm',
		    'n', 'p', 'r', 's', 't', 'v', 'w', 'x' }; 
  
  *r++ = 'x';
  
  while( i < s->length/2 )
    {
      assert( i*2+1 < s->length );

      a = (((q[i*2] >> 6) & 3) + lsh_string_bubblebabble_c( s, i+1 )) % 6;
      b = (q[i*2] >> 2) & 15;
      c = ((q[i*2] & 3) + lsh_string_bubblebabble_c( s, i+1 )/6 ) % 6;
      d = (q[i*2+1] >> 4) & 15; 
      e = (q[i*2+1]) & 15;
 
      *r++ = vowels[a];
      *r++ = cons[b];
      *r++ = vowels[c];
      *r++ = cons[d];
      *r++ = '-';
      *r++ = cons[e];

      i++;
    }

  if( s->length % 2 ) /* Odd length? */
    {
      a = (((q[s->length-1] >> 6) & 3) + lsh_string_bubblebabble_c( s, i+1 )) % 6;
      b = (q[s->length-1] >> 2) & 15;
      c = ((q[s->length-1] & 3) + lsh_string_bubblebabble_c( s, i+1 )/6 ) % 6;
    }
  else
    {
      a = lsh_string_bubblebabble_c( s, i+1 ) % 6;
      b = 16;
      c = lsh_string_bubblebabble_c( s, i+1 ) / 6;
    }

  *r++ = vowels[a];
  *r++ = cons[b];
  *r++ = vowels[c];
  
  *r++ = 'x';
  *r++ = 0;

  if( freeflag )
    lsh_string_free( s );

  return p;
}
