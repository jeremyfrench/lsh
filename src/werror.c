/* werror.c
 *
 */

#include "werror.h"

#include <stdio.h>
#include <stdarg.h>

int debug_flag = 0;
int quiet_flag = 0;

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

/* Escape non-printable characters. */
void werror_washed(UINT32 length, UINT8 *msg)
{
  int i;

  for(i = 0; i<lengh; i++)
    {
      switch(msg[i])
	{
	case '\\':
	  fputs("\\\\", stderr);
	  break;
	case '\r':
	  /* Ignore */
	  break;
	default:
	  if (!isprint(msg[i]))
	    {
	      fprintf("\\x%2x", msg[i]);
	      break;
	    }
	  /* Fall through */
	case '\n':
	  putc('\n', stderr);
	  break;
	}
    }
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

void fatal(char *format, ...) 
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  abort();
}
