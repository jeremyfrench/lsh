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
#include "gc.h"
#include "io.h"
#include "parse.h"

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>

int debug_flag = 0;
int quiet_flag = 0;
int verbose_flag = 0;

int error_fd = STDERR_FILENO;

#define BUF_SIZE 500
static UINT8 error_buffer[BUF_SIZE];
static UINT32 error_pos = 0;

static int (*error_write)(int fd, UINT32 length, UINT8 *data) = write_raw;

#define WERROR(l, d) (error_write(error_fd, (l), (d)))

static void werror_flush(void)
{
  if (error_pos)
    {
      WERROR(error_pos, error_buffer);
      error_pos = 0;
    }
}

static void werror_putc(UINT8 c)
{
  if (error_pos == BUF_SIZE)
    werror_flush();

  error_buffer[error_pos++] = c;
}

void set_error_stream(int fd, int with_poll)
{
  error_fd = fd;

  error_write = with_poll ? write_raw_with_poll : write_raw;
}

void wwrite(char *msg)
{
  if (!quiet_flag)
    {
      UINT32 size = strlen(msg);

      if (error_pos + size <= BUF_SIZE)
	{
	  memcpy(error_buffer + error_pos, msg, size);
	  error_pos += size;
      
	  if (size && (msg[size-1] == '\n'))
	    werror_flush();	
	}
      else
	{
	  werror_flush();
	  WERROR(size, msg);
	}
    }
}

#ifdef HAVE_VSNPRINTF
/* FIXME: Too bad we can't create a custom FILE * using werror_putc to
 * output each character. */
static void w_vnprintf(unsigned size, const char *format, va_list args)
{
  int written;
  
  if (error_pos + size <= BUF_SIZE)
    {
      written = vsnprintf(error_buffer + error_pos, size, format, args);

      error_pos += (written >= 0) ? written : size;
    }
  else
    {
      UINT8 *s = alloca(size);

      werror_flush();
      written = vsnprintf(s, size, format, args);

      if (written >= 0)
	size = written;
      
      WERROR(size, s);
    }
}
#else /* !HAVE_VSNPRINTF */

#warning No vsnprintf. Some output to stderr will be lost.

static void w_vnprintf(unsigned size, const char *format, va_list args)
{
  /* NOTE: This loses the interesting parts of the messages. */
  wwrite(format);
}
#endif /* !HAVE_VSNPRINTF */

static void w_nprintf(UINT32 size, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  w_vnprintf(size, format, args);
  va_end(args);
}

#define WERROR_MAX 150
void werror(const char *format, ...) 
{
  va_list args;

  if (!quiet_flag)
    {
      va_start(args, format);
      w_vnprintf(WERROR_MAX, format, args);
      va_end(args);
      werror_flush();
    }
}

void debug(const char *format, ...) 
{
  va_list args;

  if (debug_flag)
    {
      va_start(args, format);
      w_vnprintf(WERROR_MAX, format, args);
      va_end(args);
      werror_flush();
    }
}

void verbose(const char *format, ...) 
{
  va_list args;

  if (verbose_flag)
    {
      va_start(args, format);
      w_vnprintf(WERROR_MAX, format, args);
      va_end(args);
      werror_flush();
    }
}

static void wash_char(UINT8 c)
{
  static const char hex[16] = "0123456789abcdef";
  
  switch(c)
    {
    case '\\':
      werror_putc('\\');
      werror_putc('\\');
      break;
    case '\r':
      /* Ignore */
      break;
    default:
      if (!isprint(c))
	{
	  werror_putc('\\');
	  werror_putc(hex[c / 16]);
	  werror_putc(hex[c % 16]);
	  break;
	}
      /* Fall through */
    case '\n':
      werror_putc(c);
      break;
    }
}

/* Escape non-printable characters. */
static void write_washed(UINT32 length, UINT8 *msg)
{
  UINT32 i;

  for(i = 0; i<length; i++)
    wash_char(msg[i]);

  werror_flush();
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
	  werror_putc('\\');
	  werror_putc('!');
	  return;
	case 1:
	  {
	    int local = ucs4_to_local(ucs4);
	    if (local < 0)
	      {
		werror_putc('\\');
		werror_putc('?');
	      }
	    else
	      wash_char(local);
	    break;
	  }
	default:
	  fatal("Internal error");
	}
    }
  werror_flush();
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
static void write_mpz(mpz_t n)
{
  UINT8 *s = alloca(mpz_sizeinbase(n, 16) + 2);
  mpz_get_str(s, 16, n);

  WERROR(strlen(s), s);
}

void werror_mpz(mpz_t n)
{
  if (!quiet_flag)
    write_mpz(n);
}

void debug_mpz(mpz_t n)
{
  if (debug_flag)
    write_mpz(n);
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
  
  w_nprintf(40, "(size %d = 0x%x)", length, length);

  for(i=0; i<length; i++)
  {
    if (! (i%16))
      w_nprintf(20, "\n%08x: ", i);
    
    w_nprintf(4, "%02x ", data[i]);
  }
  w_nprintf(2, "\n");
  werror_flush();
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
  w_vnprintf(WERROR_MAX, format, args);
  va_end(args);
  werror_flush();

  abort();
}
