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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <assert.h>
#include <string.h>

#include "format.h"
#include "werror.h"
#include "xalloc.h"

struct lsh_string *ssh_format(char *format, ...)
{
  va_list args;
  UINT32 length;
  struct lsh_string *packet;

  va_start(args, format);
  length = ssh_vformat_length(format, args);
  va_end(args);

  packet = lsh_string_alloc(length);

  va_start(args, format);
  length = ssh_vformat(format, packet->data, args);
  va_end(args);

  assert(length == packet->length);
  
  return packet;
}
 
UINT32 ssh_vformat_length(char *f, va_list args)
{
  UINT32 length = 0;

  while(*f)
    {
      if (*f == '%')
	{
	  int literal = 0;
	  f++;
	  while(*f)
	    {
	      if (*f == 'l')
		{
		  literal = 1;
		  f++;
		}
	      else if (*f == 'f')
		{
		  f++;
		}
	      else break;
	    }
	  
	  switch(*f)
	    {
	    default:
	      fatal("ssh_vformat_length: bad format string");
	      break;

	    case 'c':
	      (void) va_arg(args, UINT8);
	      /* Fall through */
	    case '%':
	      f++;
	      length++;
	      break;

	    case 'i':
	      (void) va_arg(args, UINT32);
	      f++;
	      length += 4;
	      break;

	    case 's':
	      {
		length += va_arg(args, UINT32); /* String length */

		(void) va_arg(args, UINT8 *);    /* data */

		f++;
		
		if (!literal)
		  length += 4;

		break;
	      }
	    case 'S':
	      length += va_arg(args, struct lsh_string *)->length;
	      f++;

	      if (!literal)
		length += 4;
	      
	      break;
	    case 'z':
	      length += strlen(va_arg(args, char*));
	      f++;

	      if (!literal)
		length += 4;
	      break;
	    case 'r':
	      length += va_arg(args, UINT32);
	      (void) va_arg(args, UINT8 **);    /* pointer */

	      f++;

	      if (!literal)
		length += 4;
	      break;
	    case 'a':
	      {
		int atom = va_arg(args, int);

		assert(atom);

		length += get_atom_length(atom);

		if (!literal)
		  length += 4;
		f++;
		break;
	      }
	    case 'A':
	      {
		int *atom = va_arg(args, int *);
		int i;

		if (atom[0])
		  { /* Non empty */
		    for(i = 0; atom[i] > 0; i++)
		      length += get_atom_length(atom[i]) + 1;

		    /* One ','-character less than the number of atoms */
		    length--;
		  }
		if (!literal)
		  length += 4;
		f++;
		break;
	      }
#if 0
	    case 'A':
	      {
		int atom;

		while ( (atom = va_arg(args, int)) )
		  length += get_atom_length(atom) + 1;

		/* One ','-character less than the number of atoms */
		length--;
		
		if (!literal)
		  length += 4;
		f++;
		break;
	      }
#endif
	    case 'n':
	      {
		MP_INT *n = va_arg(args, MP_INT*);

		/* Calculate length of written number */
		length += bignum_format_s_length(n);

		if (!literal)
		  length += 4;
		f++;
		break;
	      }
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

UINT32 ssh_vformat(char *f, UINT8 *buffer, va_list args)
{
  UINT8 *start = buffer;
  
  while(*f)
    {
      if (*f == '%')
	{
	  int literal = 0;
	  int do_free = 0;
	  f++;
	  while(*f)
	    {
	      if (*f == 'l')
		{
		  literal = 1;
		  f++;
		}
	      else if (*f == 'f')
		{
		  do_free = 1;
		  f++;
		}
	      else break;
	    }
	  switch(*f)
	    {
	    default:
	      fatal("ssh_vformat: bad format string");
	      break;

	    case 'c':
	      *buffer++ = va_arg(args, int);
	      f++;

	      break;
	    case '%':
	      *buffer++ = '%';
	      f++;

	      break;

	    case 'i':
	      {
		UINT32 i = va_arg(args, UINT32);
		WRITE_UINT32(buffer, i);
		buffer += 4;
		f++;

		break;
	      }
	    case 's':
	      {
		UINT32 length = va_arg(args, UINT32);
		UINT8 *data = va_arg(args, UINT8 *);

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		memcpy(buffer, data, length);
		buffer += length;
		f++;

		break;
	      }
	    case 'S':
	      {
		struct lsh_string *s = va_arg(args, struct lsh_string *);

		if (!literal)
		  {
		    WRITE_UINT32(buffer, s->length);
		    buffer += 4;
		  }

		memcpy(buffer, s->data, s->length);
		buffer += s->length;

		if (do_free)
		  lsh_string_free(s);
		f++;

		break;
	      }
	    case 'z':
	      {
		char *s = va_arg(args, char *);
		UINT32 length = strlen(s);
		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		memcpy(buffer, s, length);
		buffer += length;
		f++;

		break;
	      }
	    case 'r':
	      {
		UINT32 length = va_arg(args, UINT32);
		UINT8 **p = va_arg(args, UINT8 **);

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		if (p)
		  *p = buffer;
		buffer += length;
		f++;

		break;
	      }
	    
	    case 'a':
	      {
		UINT32 length;
		int atom = va_arg(args, int);
		
		assert(atom);

		length = get_atom_length(atom);

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		memcpy(buffer, get_atom_name(atom), length);
		buffer += length;
		f++;

		break;
	      }
#if 0
	    case 'A':
	      {
		int atom;
		UINT8 *start = buffer; /* Where to store the length */
		
		if (!literal)
		  buffer += 4;

		atom = va_arg(args, int);
		if (atom)
		  {
		    UINT32 length = get_atom_length(atom);
		    memcpy(buffer, get_atom_name(atom), length);
		    buffer += length;

		    while ( (atom = va_arg(args, int)) )
		      {
			*buffer++ = ',';
			length = get_atom_length(atom);
			memcpy(buffer, get_atom_name(atom), length);
			buffer += length;
		      }
		  }
				
		if (!literal)
		  {
		    UINT32 total = buffer - start - 4;
		    WRITE_UINT32(start, total);
		  }
		f++;
		break;
	      }
#endif
	    case 'A':
	      {
		int *atom = va_arg(args, int *);
		UINT8 *start = buffer; /* Where to store the length */
		int i;
		
		if (!literal)
		  buffer += 4;

		if (atom[0] > 0)
		  {
		    UINT32 length = get_atom_length(atom[0]);
		    memcpy(buffer, get_atom_name(atom[0]), length);
		    buffer += length;
		    
		    for (i = 1; atom[i] > 0; i++)
		      {
			*buffer++ = ',';
			length = get_atom_length(atom[i]);
			memcpy(buffer, get_atom_name(atom[i]), length);
			buffer += length;
		      }
		  }
				
		if (!literal)
		  {
		    UINT32 total = buffer - start - 4;
		    WRITE_UINT32(start, total);
		  }
		f++;
		break;
	      }
	    case 'n':
	      {
		MP_INT *n = va_arg(args, MP_INT *);
		UINT32 length = bignum_format_s(n, buffer);

		buffer += length;

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		f++;

		break;
	      }
	    }
	}
      else
	{
	  *buffer++ = *f++;
	}
    }
  return buffer - start;
}
