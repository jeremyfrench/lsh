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

#include "charset.h"
#include "parse.h"

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

int debug_flag = 0;
int quiet_flag = 0;
int verbose_flag = 0;

void werror(const char *format, ...) 
{
  va_list args;

  if (!quiet_flag)
    {
      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

void debug(const char *format, ...) 
{
  va_list args;

  if (debug_flag)
    {
      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

void verbose(const char *format, ...) 
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
static void write_washed(UINT32 length, UINT8 *msg)
{
  UINT32 i;

  for(i = 0; i<length; i++)
    wash_char(msg[i]);
}

/* For outputting data received from the other end */
void werror_safe(UINT32 length, UINT8 *msg)
{
  if (!quiet_flag)
    write_washed(length, msg);
}

void debug_safe(UINT32 length, UINT8 *msg)
{
  if (debug_flag)
    write_washed(length, msg);
}

void verbose_safe(UINT32 length, UINT8 *msg)
{
  if (verbose_flag)
    write_washed(length, msg);
}

static void write_utf8(UINT32 length, UINT8 *msg)
{
  struct simple_buffer buffer;
  
  simple_buffer_init(&buffer, length, msg);
  
  while(1)
    {
      UINT32 ucs4;
      
      switch (parse_utf8(&buffer, &ucs4))
	{
	case -1:
	  return;
	case 0:
	  fputs("\\!", stderr);
	  return;
	case 1:
	  {
	    int local = ucs4_to_local(ucs4);
	    if (local < 0)
	      fputs("\\?", stderr);
	    else
	      wash_char(local);
	    break;
	  }
	default:
	  fatal("Internal error");
	}
    }
}

void werror_utf8(UINT32 length, UINT8 *msg)
{
  if (!quiet_flag)
    write_utf8(length, msg);
}

void verbose_utf8(UINT32 length, UINT8 *msg)
{
  if (verbose_flag)
    write_utf8(length, msg);
}

void debug_utf8(UINT32 length, UINT8 *msg)
{
  if (debug_flag)
    write_utf8(length, msg);
}

/* Bignums */
void werror_mpz(mpz_t n)
{
  if (!quiet_flag)
    mpz_out_str(stderr, 16, n);
}

void debug_mpz(mpz_t n)
{
  if (debug_flag)
    mpz_out_str(stderr, 16, n);
}

void verbose_mpz(mpz_t n)
{
  if (verbose_flag)
    mpz_out_str(stderr, 16, n);
}

/* hex dumps */
static void write_hex(UINT32 length, UINT8 *data)
{
  UINT32 i;
  
  fprintf(stderr, "(size %d = 0x%x)",
	  length, length);

  for(i=0; i<length; i++)
  {
    if (! (i%16))
      fprintf(stderr, "\n%08x: ", i);
    
    fprintf(stderr, "%02x ", data[i]);
  }
  fprintf(stderr, "\n");
}

void werror_hex(UINT32 length, UINT8 *data)
{
  if (!quiet_flag)
    write_hex(length, data);
}

void debug_hex(UINT32 length, UINT8 *data)
{
  if (debug_flag)
    write_hex(length, data);
}

void verbose_hex(UINT32 length, UINT8 *data)
{
  if (verbose_flag)
    write_hex(length, data);
}

void fatal(const char *format, ...) 
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  abort();
}
