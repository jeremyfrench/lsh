/* format.c
 *
 */

#include "format.h"
#include "werror.h"

#include <assert.h>
#include <string.h>

struct simple_packet *ssh_format(char *format, ...)
{
  va_list args;
  UINT32 length;
  struct simple_packet *packet;

  va_start(args, format);
  length = ssh_vformat_length(format, args);
  va_end(args);

  packet = simple_packet_alloc(length);

  va_start(args, format);
  ssh_vformat(format, packet->data, args);
  va_end(args);

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
	  if (*f == 'l')
	    {
	      literal = 1;
	      f++;
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
	      }
	      break;
	    case 'S':
	      length += va_arg(args, struct lsh_string *)->length;
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
	      }
	    break;
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
	      }
	    break;
	    case 'n':
	      {
		bignum *n = va_arg(args, bignum *);

		/* Calculate length of written number */
		length += bignum_format_length(n);

		if (!literal)
		  length += 4;
		f++;
	      }
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

void ssh_vformat(char *f, UINT8 *buffer, va_list args)
{
  while(*f)
    {
      if (*f == '%')
	{
	  int literal = 0;
	  f++;
	  if (*f == 'l')
	    {
	      literal = 1;
	      f++;
	    }
	  switch(*f)
	    {
	    default:
	      fatal("ssh_vformat: bad format string");
	      break;

	    case 'c':
	      *buffer++ = va_arg(args, UINT8);
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
	      }
	    break;
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
	      }
	    break;
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
		f++;
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
	      }
	    break;
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
	      }
	    break;
	    case 'n':
	      {
		bignum *n = va_arg(args, bignum *);
		UINT32 length = bignum_format(n, buffer);

		buffer += length;

		if (!literal)
		  {
		    WRITE_UINT32(buffer, length);
		    buffer += 4;
		  }

		f++;
	      }
	    break;
	    }
	}
      *buffer++ = *f++;
    }
}
