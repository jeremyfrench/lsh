/* werror.c
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

#include "werror.h"

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

int debug_flag = 0;
int quiet_flag = 0;
int verbose_flag = 0;

void werror(char *format, ...) 
{
  va_list args;

  if (!quiet_flag)
    {
      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

void debug(char *format, ...) 
{
  va_list args;

  if (debug_flag)
    {
      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

void verbose(char *format, ...) 
{
  va_list args;

  if (verbose_flag)
    {
      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

static void wash_char(UINT8 c)
{
  switch(c)
    {
    case '\\':
      fputs("\\\\", stderr);
      break;
    case '\r':
      /* Ignore */
      break;
    default:
      if (!isprint(c))
	{
	  fprintf(stderr, "\\x%02x", c);
	  break;
	}
      /* Fall through */
    case '\n':
      putc(c, stderr);
      break;
    }
}

/* Escape non-printable characters. */
static void werror_washed(UINT32 length, UINT8 *msg)
{
  int i;

  for(i = 0; i<length; i++)
    wash_char(msg[i]);
}

/* For outputting data recieved from the other end */
void werror_safe(UINT32 length, UINT8 *msg)
{
  if (!quiet_flag)
    werror_washed(length, msg);
}

void debug_safe(UINT32 length, UINT8 *msg)
{
  if (debug_flag)
    werror_washed(length, msg);
}

void verbose_safe(UINT32 length, UINT8 *msg)
{
  if (verbose_flag)
    werror_washed(length, msg);
}

void werror_safe_utf8(UINT32 length, UINT8 *msg)
{
  /* FIXME: This function assumes that the system charset is
   * iso-8859-1, aka latin1. */

  if (!quiet_flag)
    {
      int i=0;
      
      while(i<length)
	{
	  UINT8 c = msg[i++];
	  if (!(c & 0x80))
	    wash_char(c);
	  else
	    {
	      if ( (c & 0xd0) != 0xc0)
		{
		  /* Unicode value >= 0x800 */
		  fputs("\\?", stderr);
		  while ( (i < length) & (msg[i] & 0x80) )
		    i++;
		}
	      else
		{
		  if (i == length)
		    /* String ends with a partial character! */
		    fputs("\\!", stderr);
		  else
		    wash_char( ((c & 3) << 6) || (msg[i++] & 0x3f) ); 
		}
	    }
	}
    }
} 
  
void fatal(char *format, ...) 
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  abort();
}

void werror_mpz(mpz_t n)
{
  mpz_out_str(stderr, 16, n);
  putc('\n', stderr);
}
